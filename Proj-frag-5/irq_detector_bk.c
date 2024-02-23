/*
 *
 *
 */

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
#include <linux/kthread.h>
#include <linux/sched.h>  
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>

#define SAMPLING_INTERVAL	500L /*10 milli second*/
#define MS_TO_NS(x)		(x * 1E6L)
#define MAX_SIZE		32

#define CONFIG_SEQ_READ

struct irq_desc *irq_desc_node;
int irq;

struct irq_detector_data {
	char 				name[20];
	struct platform_device		*pdev;
	struct mutex			mutex_lock;
	struct proc_dir_entry		*proc_dir;
	struct proc_dir_entry		*proc_file;
	unsigned long			irq_interval_threshold_us;
	atomic_t 			inst_irq_rate;
	void				*virt_addr;
	phys_addr_t			phys_addr;
	int				irq;
	struct irq_desc 		*desc;

	unsigned long                   irq_timestamp;
	unsigned long                   last_irq_timestamp;
	struct hrtimer 			mhr_timer;
	struct task_struct		*irq_poll_thread;
};

static u8 *procfs_test_buffer;

enum hrtimer_restart read_irq_interval_cb( struct hrtimer *timer )
{
	//pr_info( "my_hrtimer_callback called (%ld).\n", jiffies );

	struct irq_detector_data *mirq_data;
	mirq_data = container_of(timer, struct irq_detector_data, mhr_timer);

 	for_each_irq_desc(irq, irq_desc_node) {

                pr_alert("IRQ# - %d, IRQ inst rate = %d\n", 
				irq_desc_node->irq_data.irq, 
				((irq_desc_node->irq_count)/SAMPLING_INTERVAL));
        }

    return HRTIMER_RESTART;
}

/*Thread*/
int thread_function(void *pv)
{
	int i=0;
	unsigned long temp_timestamp;
	struct irq_detector_data *mirq_data = pv;

	for_each_irq_desc(irq, irq_desc_node) {

                pr_alert("IRQ name - %s\n", irq_desc_node->name);
	}
#if 1
	while(!kthread_should_stop()) {
	//pr_alert("In IRQ Poll Thread Function %d\n", i++);
	//msleep(1000);
	for_each_irq_desc(irq, irq_desc_node) {

		//pr_alert("IRQ name - %s\n", irq_desc_node->name);
		if(irq_desc_node && !(irq_desc_node->irq_count % 1000)) { //1000 -> 5 for debugging

			if(time_before(jiffies, 
				mirq_data->last_irq_timestamp + HZ/10)) {
				pr_alert(" Interrupt storm detected");
			}
			//pr_alert("DBG: In func - %s, Line - %d\n", __func__, __LINE__);
			mirq_data->last_irq_timestamp = jiffies;
                }
        }

	/*if( ) {

	}*/

    }
#endif
    return 0;
}

#if 0
/*Read Irq data*/
static void read_irq_data(void)
{
	for_each_irq_desc(irq, irq_desc_node) {
		pr_alert("irq_detect: Linux Irq No. - %d, Hw Irq No. - %lu, Last unhandled - %lu\n",
			irq_desc_node->irq_data.irq, irq_desc_node->irq_data.hwirq,
			irq_desc_node->last_unhandled);
	}
}
#endif

static void log_irq_timestamp(void)
{

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

static int create_proc_entry(struct irq_detector_data *mirq_data)
{
	if(mirq_data == NULL)
		return -EINVAL;

	mirq_data->proc_dir = proc_mkdir("irq_diag",NULL);
	if(!mirq_data->proc_dir) {
		pr_err("DBG: Error creating proc directory\n");
		return -ENOMEM;
	}

	scnprintf(mirq_data->name, 20, "irq_storm_stat");
	mirq_data->proc_file = proc_create(mirq_data->name, 
			S_IWUSR | S_IRUSR, mirq_data->proc_dir, &procfs_test_pops);
        if (!mirq_data->proc_file) {
                return -ENOMEM;
	}

	return 0;
}

static void delete_proc_entry(struct irq_detector_data *mirq_data)
{

	if(mirq_data == NULL)
		return;

	remove_proc_entry("irq_storm_stat", mirq_data->proc_dir);
	remove_proc_entry("irq_diag", NULL);
}

static int irq_detector_probe(struct platform_device *pdev)
{
	struct irq_detector_data *mirq_data;
	struct device *dev = &pdev->dev;
	struct device_node *np;
	int ret = 0;
	ktime_t ktime;
	unsigned long delay_in_ms = SAMPLING_INTERVAL;

	if(dev == NULL) {
		ret = -EINVAL;
		goto probe_fail;
	}
	np = pdev->dev.of_node;

	mirq_data = devm_kzalloc(dev, sizeof(*mirq_data), GFP_KERNEL);
        if (!mirq_data)
                return -ENOMEM;

	mirq_data->irq_timestamp = jiffies;

	ktime = ktime_set(0, MS_TO_NS(delay_in_ms) );

	hrtimer_init(&mirq_data->mhr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mirq_data->mhr_timer.function = &read_irq_interval_cb;

	pr_info("Starting timer to fire in %ldms (%ld)\n", \
					delay_in_ms, jiffies );

	hrtimer_start(&mirq_data->mhr_timer, ktime, HRTIMER_MODE_REL);

	platform_set_drvdata(pdev, mirq_data);

	//procfs_test_buffer = kmalloc(MAX_SIZE, GFP_KERNEL);
	//if (!procfs_test_buffer)
	//	return -ENOMEM;

	ret = create_proc_entry(mirq_data);
	if(ret < 0) {
		pr_alert("DBG: proc file creation failed!");
		goto probe_fail;
	}

	mirq_data->irq_poll_thread = kthread_create(thread_function, 
					mirq_data, "Irq Poll Thread");
	if (IS_ERR(mirq_data->irq_poll_thread))
		return PTR_ERR(mirq_data->irq_poll_thread);

        if(mirq_data->irq_poll_thread) {
            wake_up_process(mirq_data->irq_poll_thread);
        } else {
            pr_err("Cannot create kthread\n");
            goto probe_fail;
        }

	pr_alert("DBG: In function - %s, Line - %d\n", __func__, __LINE__);

probe_fail:
	return ret;
}

static int irq_detector_remove(struct platform_device *pdev)
{
        struct irq_detector_data *mirq_data = platform_get_drvdata(pdev);
        int ret = 0;

	//hrtimer_cancel(&mirq_data->mhr_timer);
	kthread_stop(mirq_data->irq_poll_thread);

	delete_proc_entry(mirq_data);

	if(mirq_data)
		kfree(mirq_data);

	//if (timedata.virt_addr)
	//	vunmap(timedata.virt_addr);

	platform_set_drvdata(pdev, NULL);

	return ret;
}

static const struct of_device_id irq_detector_of_match_table[] = {
	{ .compatible = "mirfaisal,irq_detector", .data = NULL },
	{ },
};

static int devicemodel_suspend(struct device *dev)
{
	pr_info("devicemodel example suspend\n");

	/* Your device suspend code */
	return 0;
}

static int devicemodel_resume(struct device *dev)
{
	pr_info("devicemodel example resume\n");

	/* Your device resume code */

	return 0;
}

static const struct dev_pm_ops devicemodel_pm_ops = {
	.suspend = devicemodel_suspend,
	.resume = devicemodel_resume,
	.poweroff = devicemodel_suspend,
	.freeze = devicemodel_suspend,
	.thaw = devicemodel_resume,
	.restore = devicemodel_resume,
};

static struct platform_driver irq_detector_driver = {
	
	.driver = {
		.name = "devicemodel_example",
		.pm = &devicemodel_pm_ops,
	},

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
