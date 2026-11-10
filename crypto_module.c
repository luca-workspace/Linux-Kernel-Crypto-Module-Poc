/* LOGGING CONVENTION NOTE: pr_* macros vs. printk():
 * This module exclusively uses the modern pr_* macros (e.g., pr_err, pr_info) 
 * instead of the legacy printk(KERN_LEVEL ...) wrapper (e.g., KERN_INFO for an informational message, which is
 * severity level 6) for the following reasons:
 *  1. Clean Syntax: Eliminates awkward string concatenation like printk(KERN_ERR "msg").
 *  2. Automated Subsystem Tagging: When combined with a top-of-file '#define pr_fmt',
 *      every pr_* call automatically prepends the module name (KBUILD_MODNAME) to the 
 *      kernel ring buffer (dmesg). printk() requires manual string prefixes.
 *  3. Standard Optimization: Easily toggled or stripped by the compiler (especially pr_debug).
 *
 * Severity Guidance:
 *  - pr_err(): Critical failures that abort execution (e.g., alloc_chrdev_region fails).
 *  - pr_info(): Milestone events visible to sysadmins (e.g., successful driver load).
 *  - pr_debug(): Low-overhead troubleshooting strings (compiled out by default).
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt  // Prefixes all pr_* logs with the module name

// LIBRARIES
#include <linux/fs.h>       // For alloc_chrdev_region function definition
#include <linux/init.h>     // For __init and __exit macros
#include <linux/module.h>   // Required for all modules, such as this same one
                            // Also required for module_init and module_exit
#include <linux/kernel.h>   // Required for "KERN_INFO", which is a log level macro in the Linux kernel used with
                            // the printk() logging function to designate an informational message (severity level 6)
#include <linux/uaccess.h>  // Required for copy_from_user and copy_to_user functions
#include <linux/slab.h>     // Required for dynamic memory allocation using kmalloc and kfree
#include <linux/cdev.h>     // Required for cdev_init, cdev_add, struct cdev
#include <linux/mutex.h>    // Required for mutex ("mutual exclusion")

/* Note about mutex: it's a synchronization primitive used to prevent multiple threads or processes from accessing a shared resource simultaneously.
 * Because Linux separates operations into user space and kernel space, mutexes are implemented and used differently depending on where the code runs.
 * In our case, since we're writing a Linux kernel module (though it's valid for device drivers, too), we use "struct mutex". In a standard
 * application software (C/C++), we'd use the "pthread_mutex_t" API (pthread_mutex_init(), pthread_mutex_lock(), pthread_mutex_unlock(), etc.)
 * provided by the POSIX threads library.
 * The use of mutex is justified by the fact that the kernel can execute "crypto_read" and "crypto_write" from two processes simultaneously
 * (even on two different CPUs). This module's global variables "crypto_buffer" and "message_size" (defined below) are shared, so if process A
 * is calling "kfree(crypto_buffer)" while process B is calling "copy_to_user" from the same buffer, we'd have a use-after-free, i.e. a kernel crash.
 * So the mutex acts as a "padlock": only the process that holds it can enter the critical section (our two functions, one at a time); the other one is
 * blocked until the mutex is released. In interrupt handlers, we'd use spinlocks rather than mutex, since mutex can block the process.
 * We're going to call our mutex "crypto_mutex", as shown below.
 */
static DEFINE_MUTEX(crypto_mutex);

// FUNCTION PROTOTYPES
static ssize_t crypto_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos);
static ssize_t crypto_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos);
                        
/* The Linux kernel is a strictly regulated open-source ecosystem. If you try to load a module without explicitly declaring
 * a compatible licence (usually the "GPL" one) in the code, the system will raise an alarm, flagging the kernel as "Tainted", and
 * When the kernel is "Tainted", it blocks access to many advanced internal functions as a safety measure, so we define the module
 * license, choosing "GPL" this time. 
 */
MODULE_LICENSE("GPL");

/* In Linux, character and block devices are represented as special files (device nodes) located
 * in the /dev directory. The Linux kernel uses a combination of "major" and "minor" numbers to
 * identify device drivers and distinguish between the specific physical or logical devices those drivers manage.
 * The difference between major numbers and minor numbers, as well as the difference between character
 * and block devices are explained below. 
 * 
 * MAJOR vs. MINOR NUMBERS:
 *  - Major Number: Identifies the specific device driver responsible for handling the subsystem or class of device.
 *      For example, all terminal (tty) devices or SATA disk drivers use a shared major number that tells the kernel which
 *      driver code to execute.
 *  - Minor Number: Distinguishes individual device instances or partitions managed by that single driver. If you have
 *      three similar hardware sensors or multiple partitions on a hard drive, they will share the same major number
 *      but have unique minor numbers.
 * 
 * DEVICE DRIVER TYPE COMPARISON: CHARACTER vs. BLOCK DEVICES:
 * Feature:            Character Device (cdev)
 *   - Data Unit:       Stream of individual bytes
 *   - Access Pattern:  Sequential access only (no seeking backward/forward)
 *   - Kernel Buffering:No cache/buffer (direct data transfer)
 *   - File Indicator:  Marked with a 'c' in ls -l /dev
 *   - Filesystem:      Cannot host a filesystem
 *   - Typical Hardware:Keyboards, mice, serial ports, custom sensors
 * 
 * Feature:            Block Device (bdev)
 *   - Data Unit:       Fixed-size blocks (e.g., 512B, 4KB)
 *   - Access Pattern:  Random access (can jump to any block instantly)
 *   - Kernel Buffering:Uses the Linux page cache for performance
 *   - File Indicator:  Marked with a 'b' in ls -l /dev
 *   - Filesystem:      Can host filesystems (ext4, XFS, etc.)
 *   - Typical Hardware:Hard drives, SSDs, NVMe drives, USB flash drives
 */

/* The alloc_chrdev_region function used below dynamically requests and registers a range of
 * character device numbers without needing a hardcoded major number.
 * Unlike register_chrdev_region() (which requires you to manually pick and supply a known major number),
 * alloc_chrdev_region lets the kernel pick an unused major number for you.
 * Parameters are:
 *  - "dev_t *dev": (An OUTPUT parameter) A pointer to a dev_t variable where the kernel will store
 *      the first allocated device number (major + minor).
 *      "dev_t" is an integer data type used to represent device IDs. It identifies a specific device
 *      or the filesystem/storage device where a file resides. However, it's not like any integer, but rather
 *      a 32-bit data type composed by:
 *          - the first 12 bits, representing the major number (which can be extracted through the MAJOR function);
 *          - the remaining 20 bits for the minor number.
 *      Note: you pass a static dev_t unassigned variable BY REFERENCE to the function and the function
 *      will modify the value on its own.)
 *  - unsigned baseminor: The first requested minor number in the range (usually 0).
 *  - unsigned count: The total number of contiguous minor numbers requested.
 *  - const char *name: The name of the driver or device associated with this range (visible in /proc/devices).
 * Possible return values are:
 *  - 0 on success;
 *  - a negative error code on failure (e.g., if the kernel runs out of device numbers).
 */
static dev_t device_number;

/* However, the calling user program knows absolutely nothing about the kernel or your functions; it simply opens
 * a "file" (the device). The link to it is created by the kernel module, just once, within the "crypto_init" function
 * defined below, which is executed at the time of injection ("insmod"; "insert module"). So we define a C "file_operations"
 * structure, which is a sort of map of function pointers (virtual function table - vtable) that tells the kernel which
 * function to call based on whether the "file" is being read, written to, etc.
 */

static struct file_operations fops = {
    .read = crypto_read,
    .write = crypto_write,
    // .open = crypto_open,    // We're not implementing it here
    // .release = crypto_close // We're not implementing it here
};

static struct cdev crypto_cdev; // See explanation that follows the cdev_init and cdev_add functions

/* OPERATIVE FUNCTIONS
 * These functions are the operative "core" of the module, and they directly intercept system calls (i.e., requests made
 * by applications in user space). When a user app calls "fread" or "fwrite" (which translate to "read()" and "write()" at OS level)
 * on our "crypto_hw" file, the kernel redirects the call to these functions (because we specified them in the "file_operations"
 * "map"). To ensure that the "file_operations" map accepts these functions, they must have exactly the signature specified in the
 * prototypes at the top of this file. The parameters they take are the same in both cases, with the exception that in crypto_write
 * our buffer is const, because we read user input without modifying it. Parameters are:
 *  - struct file *file: it's the pointer to the kernel struct representing our open "file" (device). In this module, we'll ignore it.
 *  - (const) char __user *user_buf: it's the pointer to the buffer in RAM (ring 3: user space). The "__user" tag works as a "warning":
 *      it's a compiler attribute indicating that the pointer originates from unsafe user space memory and must not be directly
 *      dereferenced (e.g., we can't do "char c = user_buf[0]"), because it points to an unsafe area of RAM (user space). The only way
 *      to use it is to pass it to "copy_from_user" or "copy_to_user" (see below).
 *  - size_t count: it's the exact number of bytes the user requested to read/write.
*       - In the crypto_write function, it tells us how many bytes we have to extract from the user buffer (user_buf)
 *          using copy_from_user (and how much space to allocate using kmalloc).
 *      - In the crypto_read function, it tells us what the maximum number of bytes the app will accept is. If we encrypt 100 byte but the
 *          count is 50, we can only send 50 at a time.
 *  - loff_t *ppos: it's a "pointer to position". It points to the current position (offset) of the "cursor" in the "file".
 *      It's there because if a file is 1000 bytes long and the app reads the first 10 bytes, the cursor moves to position 10. The next
 *      read operation will start from 10. The kernel passes this pointer to us so that we know where to start reading or writing.
 *      We'll ignore it.
 * 
 * Return type is ssize_t (signed size):
 *  - If the operation is successful, both functions must return the number of bytes processed (e.g. return count;). This number
 *      is then passed by the OS to the C++ application, which will then know that it has successfully read or written the data.
 *  - If they fail (e.g. "copy_from_user" returns an error), they must return a negative number, which corresponds to the standard Linux
 *      error codes (e.g. "return -EFAULT;" for a memory access error).
 */

// copy_to_user: Kernel Space → User Space. Sending data back to an application during a device read() or a structured ioctl(). 0 on success; or the number of uncopied bytes on failure.
// copy_from_user: User Space → Kernel Space. Receiving configuration parameters or data payload during a device write(). 0 on success; or the number of uncopied bytes on failure.

// We declare our buffer (whose memory is to be allocated dynamically)
static char *crypto_buffer = NULL;
static size_t message_size = 0;

/*
 * Note about "size_t" and "ssize_t" data types:
 * They are integer types defined by the system to represent memory sizes and numbers of bytes. In particular:
 *  - "size_t" is unsigned. It is the type used for "sizeof" and parameters such as "count" (see below). On 64-bit systems, it is
 *      a 64-bit integer, so it can represent any possible memory size.
 *  - "ssize_t" is the signed version, with the same number of bits. It exists for functions that must return either
 *      a size or a negative error, and "size_t" cannot be negative. This is why "read()" and "write()" return "ssize_t":
 *      - "≥ 0" represents the number of bytes;
 *      - "< 0" represents an error code (-EFAULT, -ENOMEM, etc.).
 * 
 * The catch is that comparing a negative "int" with a "size_t" is dangerous. The compiler converts the "int" to an "unsigned" type,
 * and -1 becomes a huge number.
 */

static ssize_t crypto_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {
    /* Since before exiting the function we have to release the mutex (to not block the module), and since we have multiple exit points
     * ("return" instructions), we only perform the return once, in the end, after reaching the "out:" section of the code through the
     * "goto out" pattern. Since we may return a different value (which can be negative, such as in the case of "-ENOMEM"), we're declaring:
     *  - a variable that can store said value
     *  - (that variable must be of ssize_t type, which supports negative numbers, rather than size_t, which doesn't)
     */
    ssize_t return_value = count;
    
    // crypto_write takes the lock, other functions (here, crypto_read) need to wait for it to be released, and take it,
    // before being able to run.
    mutex_lock(&crypto_mutex);
    // Note: mutex_lock_interruptible() can be used if we want the user to be able to cancel the waiting by pressing Ctrl + C (kill in bash)

    // If input data is too big, trigger an error (PAGE_SIZE usually equals to 4096 byte (4 KiB). A different amount may be defined and
    // used, e.g., "#define MAX_MSG_SIZE (64 * 1024)" for 64 KiB)
    if(count > PAGE_SIZE) {
        return_value = -EINVAL; // Invalid argument
        goto out;
    }

    // We must copy from user ("count" bytes), so we first allocate memory for that many bytes
    // To avoid memory leak in case it's been assigned previously without being reset, we do it before (re)allocation
    // kfree is safe if crypto_buffer is NULL already
    kfree(crypto_buffer);
    crypto_buffer = NULL;
    // Now we allocate
    crypto_buffer = kmalloc(count, GFP_KERNEL);
    // Note: GFP_KERNEL tells the kernel that the process can be paused until enough memory is available for allocation

    // If memory allocation still fails, though:
    if (!crypto_buffer) {
        pr_err("Error: Unable to allocate memory in kernel\n");
        return_value = -ENOMEM; // "Out of memory" error code
        goto out;
    }

    // If memory allocation is successful, actually read from user
    // Arguments are: destination memory address in kernel space / source memory address in user space / total number of bytes to copy
    if(copy_from_user(crypto_buffer, user_buf, count) != 0) {
        // copy_from_user returns a value different from 0 if there are bytes that it couldn't copy (not ideal).
        // If that's the case, free memory and return memory error (EFAULT)
        kfree(crypto_buffer);
        crypto_buffer = NULL;
        return_value = -EFAULT;
        goto out;
    }

    // Save user input length
    message_size = count;

    // Perform cryptographic task
    // for loop which applies a XOR on each byte with a constant key
    for(size_t i = 0; i < count; i++) {
        crypto_buffer[i] = crypto_buffer[i] ^ 1;
    }

    out:
        mutex_unlock(&crypto_mutex);    // Release mutex IN ANY CASE, no matter the return value
        return return_value;            // "count", as assigned at declaration, if no errors triggered its re-assignment
}

// In this case, "count" value would be provided by the reading program (e.g., cat, if by bash)
static ssize_t crypto_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {
    ssize_t return_value;

    mutex_lock(&crypto_mutex);

    // If written message is of size 0 or if it's been read already, return 0 (EOF)
    if(message_size == 0 || crypto_buffer == NULL) {
        return_value = 0;
        goto out;
    }

    // If a program requests 5 bytes but the message contains 30, "copy_to_user" writes all 30 to its buffer; since it could be
    // an issue, that triggers an error.
    if(count < message_size) {
        return_value = -EINVAL; // Invalid argument
        goto out;
    }

    return_value = message_size;

    // Return output to user (copy_to_user)
    // Arguments are: destination memory address in user space / source memory address in kernel space / total number of bytes to copy
    if (copy_to_user(user_buf, crypto_buffer, message_size) != 0) {
        // copy_to_user returns a value different from 0 if there are bytes that it couldn't copy (not ideal).
        // If that's the case, free memory, mark as read (message_size = 0;) and return memory error (EFAULT)
        kfree(crypto_buffer);
        crypto_buffer = NULL;
        message_size = 0;
        return_value = -EFAULT;
        goto out;
    }

    kfree(crypto_buffer); // Free previously allocated memory
    crypto_buffer = NULL; // Specified to prevent use after freeing, which would cause kernel panic
    message_size = 0; // Mark as read
    pr_info("Memory freed successfully\n");

    out:
        mutex_unlock(&crypto_mutex);
        return return_value; // return_value = message_size if no errors occurred
}

/* LIFECYCLE FUNCTIONS: crypto_init and crypto_exit
 * The kernel calls them at two specific points: when you run "insmod" and when you run "rmmod".
 * Parameters (void): None. The kernel does not pass any data to the module when loading or unloading it.
 *  - The only thing the kernel is interested in is whether the loading was successful, which is why "crypto_init" returns
 *      an "int" (0 for success, a negative number for an error).
 *  - The "exit" function returns nothing ("void") because if a module is unloaded, there is little the system can do
 *      if something goes wrong during the clean-up process.
*/

// Entry function
static int __init crypto_init(void) {
    int result;
    // Request a dynamic major number; we only need a single minor node (0)
    result = alloc_chrdev_region(&device_number, 0, 1, "crypto_hw");

    if(result < 0) {
        // Fail early if we can't secure device numbers; no resources to clean up yet
        pr_err("Failed to allocate character device region: %d\n", result);
        return result; 
    }

    // Continue with cdev initialization only after success
    /* The cdev_init function initializes a struct cdev object by linking it to the driver's
     * file operations (struct file_operations). It sets up the internal fields of the cdev structure
     * and remembers the pointer to your fops (such as open, read, write, release), preparing the structure
     * to be added to the system. It takes two parameters:
     *  - struct cdev *cdev
     *  - const struct file_operations *fops)
     */
    /* The cdev_add() function registers the initialized character device with the kernel,
     * making it live and active immediately. It inserts the device into the kernel's internal char device hash/lookup tables.
     * As soon as this function succeeds (returning 0), user-space programs can potentially access the device
     * (assuming device nodes in /dev have been created). A negative error code is returned if registration fails.
     * It takes three parameters:
     *  - struct cdev *cdev: the pointer to the initialized struct cdev structure.
     *  - dev_t dev: the first device number (dev_t) assigned to this device (combining major and minor numbers).
     *  - unsigned count: the number of minor numbers corresponding to this device.
     */

    // By setting the owner of the cdev, the kernel prevents the use of "rmmod" while the device is still open. Without this,
    // we could unload the module while a read operation is in progress, and cause the system to crash, which is why we set it
    // BEFORE registering our device with the kernel (important in a high-traffic scenario).
    crypto_cdev.owner = THIS_MODULE;
  
    cdev_init(&crypto_cdev, &fops);
    result = cdev_add(&crypto_cdev, device_number, 1);

    if (result < 0) {
        // Clean up if subsequent steps fail
        unregister_chrdev_region(device_number, 1);
        return result;
    }

    pr_info("Module initialized successfully. Major number is: %d\n", MAJOR(device_number));
    
    return 0;
}

// Exit function
static void __exit crypto_exit(void) {
    cdev_del(&crypto_cdev);
    unregister_chrdev_region(device_number, 1);

    // Free memory, in case it was allocated before
    kfree(crypto_buffer);

    pr_info("Module removed.\n");
}

// module_init and module_exit are the core macros used in Linux kernel development to define a driver or
// loadable kernel module's entry and exit points. It's defined in <linux/init.h>.
module_init(crypto_init);
module_exit(crypto_exit);

/* MODULE INJECTION:
 * Run make (to get *.ko, i.e., kernel object, file)
 * Run sudo insmod *.ko
 * 
 * Get assigned major number by checking among the 10 most recently added kernel records (use sudo if "Operation not permitted"):
 * - (sudo) dmesg | tail -n 10
 *      ALTERNATIVELY: cat /proc/devices | grep crypto_hw
 * Create the device:
 * - sudo mknod /dev/crypto_hw c [MAJOR_NUMBER] 0
 * Note: The mknod command and system call in Unix-like operating systems (such as Linux) are used to create device
 * special files (block or character devices, like ours!)
 * 
 * Give permission:
 * - sudo chmod 666 /dev/crypto_hw
 * 
 * To write (encrypt):
 * - echo -n "Hello, how's it going today?" > /dev/crypto_hw
 * To read (encrypted result):
 * - cat /dev/crypto_hw
 * 
 * MODULE REMOVAL:
 * - sudo rmmod crypto_module
 * - sudo rm /dev/crypto_hw
*/
