#include <linux/kernel_stat.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/minmax.h>
#include <linux/seq_file.h>
#include <linux/irq.h>
#include <linux/irqnr.h>
#include <linux/irqdesc.h>
#include <linux/of.h>

#define MAX_SIZE	32
#define CONFIG_SEQ_READ

struct irq_desc *irq_desc_node;
int irq;

struct irq_detector_data {
	char 				name[10];
	struct platform_device		*pdev;
	struct mutex			lock;
	struct proc_dir_entry		*proc_file;
	unsigned long			irq_interval_threshold_us;
	void				*virt_addr;
	phys_addr_t			phys_addr;
	int				irq;
	struct irq_desc 		*desc;
};

static u8 *procfs_test_buffer;

/*Read Irq data*/
static void read_irq_data(void)
{
	for_each_irq_desc(irq, irq_desc_node) {
		pr_alert("irq_detect: Linux Irq No. - %d, Hw Irq No. - %lu, Last unhandled - %lu\n",
			irq_desc_node->irq_data.irq, irq_desc_node->irq_data.hwirq,
			irq_desc_node->last_unhandled);
	}
}

static int show_irq_statistics(struct seq_file *seq, void *pdata)
{
//	seq_puts(seq, "Open Boottime\n");
//	seq_printf(seq, "Base(0x%lx) Size(0x%lx)\n", timedata.phys_addr,
//		 timedata.size);

	unsigned long phys_addr = 0x100;
	unsigned long size = 0x30;

	unsigned long irq_cnt = kstat_irqs_cpu(152, 0);

	seq_printf(seq, "Base(0x%lx) Size(0x%lx)\n", phys_addr, size);
	seq_printf(seq, "IRQ count - %ld\n", irq_cnt);

	//read_irq_data();

	for_each_irq_desc(irq, irq_desc_node) {
		if(irq_desc_node) {
			seq_printf(seq, "irq_detect: Linux Irq No. - %d, Hw Irq No. - %lu, Last unhandled - %lu\n",
				irq_desc_node->irq_data.irq, irq_desc_node->irq_data.hwirq,
				irq_desc_node->last_unhandled);
		} 
	}

	return 0;
}

static int procfs_test_open(struct inode *inode, struct file *file)
{
	/*  */
	//struct platform_device *pdev = PDE_DATA(inode);
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

static ssize_t procfs_test_write(struct file *filep, const char __user *buf,
      size_t length, loff_t *off)
{
	unsigned long n;
	unsigned int irq_cnt = 0;

	n = copy_from_user(procfs_test_buffer, buf, length);

	//irq_cnt = kstat_irqs_cpu(152, 0);
	//struct irq_desc *desc = irq_data_to_desc(152);
	//pr_alert("DBG: String: %s, length - %d, irq_cnt - %ld\n", procfs_test_buffer, length, irq_cnt);
	return length;
}

static ssize_t procfs_test_read(struct file *filep, char __user *user_buf, 
		size_t length, loff_t *offset)
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

		if(*offset < (loff_t)len_str)  /*Check for user buffer guard i.e. str[13]*/
			pstr += *offset;
		else
			return -EFAULT;

		ret = copy_to_user(user_buf, pstr, bytes);
		if(ret) {

			return -EFAULT;

		} else {

			*offset += bytes;
			pr_info("DBG: length - %d, bytes - %lu, *offset - %llu\n", length, bytes, *offset);
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

#ifndef CONFIG_SEQ_READ
	.proc_read = procfs_test_read,
#else
	.proc_read = seq_read,
#endif

	.proc_release = procfs_test_release,
};

static int irq_detector_probe(struct platform_device *pdev)
{

	struct irq_detector_data *mirq_data;
	struct device *dev = &pdev->dev;
	struct device_node *np;
	int ret = 0;

	//char name[10];

	if(dev == NULL) {
		ret = -EINVAL;
		goto probe_fail;
	}
	np = pdev->dev.of_node;

	mirq_data = devm_kzalloc(dev, sizeof(*mirq_data), GFP_KERNEL);
        if (!mirq_data)
                return -ENOMEM;

	platform_set_drvdata(pdev, mirq_data);

	//procfs_test_buffer = kmalloc(MAX_SIZE, GFP_KERNEL);
	//if (!procfs_test_buffer)
	//	return -ENOMEM;

	mirq_data->proc_file = proc_create("test_procfs_rw", S_IWUSR | S_IRUSR, NULL, &procfs_test_pops);
	if (!mirq_data->proc_file)
		return -ENOMEM;

	pr_alert("DBG: In function - %s, Line - %d\n", __func__, __LINE__);
probe_fail:
	return ret;
}

static int irq_detector_remove(struct platform_device *pdev)
{
        struct irq_detector_data *mirq_data = platform_get_drvdata(pdev);
        int ret = 0;

	if(mirq_data)
		kfree(mirq_data);

	//if (timedata.virt_addr)
	//	vunmap(timedata.virt_addr);

	remove_proc_entry("test_procfs_rw", NULL);

	platform_set_drvdata(pdev, NULL);

	return ret;
}

static const struct of_device_id irq_detector_of_match_table[] = {
	{ .compatible = "mirfaisal,irq_detector", .data = NULL },
	{ },
};

static struct platform_driver irq_detector_driver = {
	.probe = irq_detector_probe,
	.remove = irq_detector_remove,
	.driver = {
		.name = "irq_detector",
		.owner = THIS_MODULE,
		.of_match_table = irq_detector_of_match_table,
	}
};

module_platform_driver(irq_detector_driver);

MODULE_AUTHOR("Mir Faisal <mirfaisalfos@gmail.com>");
MODULE_DESCRIPTION("IRQ Detector");
MODULE_LICENSE("GPL");
