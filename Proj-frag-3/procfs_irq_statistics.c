
//#include <linux/fs.h>

#include <linux/kernel_stat.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/minmax.h>
#include <linux/seq_file.h>
#include <linux/irqnr.h>
#include <linux/irqdesc.h>

#define MAX_SIZE	32

static struct proc_dir_entry *entry;

static u8 *procfs_test_buffer;

static int show_irq_statistics(struct seq_file *seq, void *pdata)
{
//	seq_puts(seq, "Open Boottime\n");
//	seq_printf(seq, "Base(0x%lx) Size(0x%lx)\n", timedata.phys_addr,
//		 timedata.size);

	unsigned long phys_addr = 0x100;
	unsigned long size = 0x30;

	seq_printf(seq, "Base(0x%lx) Size(0x%lx)\n", phys_addr, size);
	return 0;
}

static int procfs_test_open(struct inode *inode, struct file *file)
{
	/*  */
	struct platform_device *pdev = pde_data(inode);
	int ret;

	ret = single_open(file, show_irq_statistics, pdev);

	return ret;
}

static int procfs_test_release(struct inode *inode, struct file *file)
{
	int res = single_release(inode, file);

	return res;
}

static ssize_t procfs_test_write(
      struct file *filep, const char __user *buf,
      size_t length, loff_t *off)
{
    unsigned long n;
    unsigned int irq_cnt = 0;

    n = copy_from_user(procfs_test_buffer, buf, length);

    //irq_cnt = kstat_irqs_cpu(152, 0);
	struct irq_desc *desc = irq_data_to_desc(152);
    pr_alert("DBG: String: %s, length - %d, irq_cnt - %ld\n", procfs_test_buffer, length, irq_cnt);
    return length;
}

static ssize_t procfs_test_read(
	struct file *filep, char __user *user_buf, size_t length, loff_t *offset)
{
	char str[13] = "HelloWorld!\n";
	char *pstr;
	ssize_t bytes;

	int len_str = sizeof(str);
	ssize_t ret = len_str;

	bytes = min(len_str, length);

	pstr = str;

	//kstat_irqs_cpu(irq, cpu);

	if(bytes) { 

		if(*offset < len_str)  /*Check for user buffer guard i.e. str[13]*/
			pstr += *offset;
		else 
			return -EFAULT;

		ret = copy_to_user(user_buf, pstr, bytes);
		if(ret) {

			return -EFAULT;

		} else {

			*offset += bytes;
			pr_info("DBG: length - %d, bytes - %d, *offset - %ld\n", length, bytes, *offset);
		}
	}

#if 0
	if (*offset >= len || copy_to_user(buf, s, len)) {
		pr_info("copy_to_user failed\n");
		ret = 0;
	} else {
		pr_info("procfile read %s\n", 
				filep->f_path.dentry->d_name.name);
		*offset += len;
	}
#endif
	return bytes;	
}

static struct proc_ops procfs_test_pops = {
	.proc_open = procfs_test_open,
	.proc_write = procfs_test_write,
	//.proc_read = procfs_test_read,
	.proc_read = seq_read,
	.proc_release = procfs_test_release,
};

static int __init procfs_test_init(void)
{
    procfs_test_buffer = kmalloc(MAX_SIZE, GFP_KERNEL);
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
