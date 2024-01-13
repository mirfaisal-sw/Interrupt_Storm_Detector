
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static struct proc_dir_entry *entry;

static u8 *procfs_test_buffer;

static ssize_t procfs_test_write(
      struct file *filep, const char __user *buf,
      size_t length, loff_t *off)
{
    unsigned long n;
    n = copy_from_user(procfs_test_buffer, buf, length);
    pr_alert("DBG: String: %s, length - %d\n", procfs_test_buffer, length);
    return length;
}

static ssize_t procfs_test_read(
	struct file *filep, char __user *buf, size_t length, loff_t *offset)
{
	char s[13] = "HelloWorld!\n";
	int len = sizeof(s);
	ssize_t ret = len;

	//if (*offset >= len || copy_to_user(buf, s, len)) {
	//if (copy_to_user(buf, s, len)) {
	
	if (*offset >= len || copy_to_user(buf, s, len)) {
		pr_info("copy_to_user failed\n");
		ret = 0;
	} else {
		pr_info("procfile read %s\n", 
				filep->f_path.dentry->d_name.name);
		*offset += len;
	}

	return ret;	
}

static struct proc_ops procfs_test_pops = {
    .proc_write = procfs_test_write,
    .proc_read = procfs_test_read,
};

static int __init procfs_test_init(void)
{
    procfs_test_buffer = kmalloc(14, GFP_KERNEL);
    if (!procfs_test_buffer)
        return -ENOMEM;

    entry = proc_create("test_procfs_rw", S_IWUSR | S_IRUSR, NULL, &procfs_test_pops);
    if (!entry)
        return -ENOMEM;

    return 0;
}

static void procfs_test_exit(void)
{
    kfree(procfs_test_buffer);
    remove_proc_entry("test_procfs_rw", NULL);
}

MODULE_AUTHOR("Mir Faisal <mirfaisalfos@gmail.com>");
MODULE_DESCRIPTION("Testing KASAN");
MODULE_LICENSE("GPL");

module_init(procfs_test_init);
module_exit(procfs_test_exit);
