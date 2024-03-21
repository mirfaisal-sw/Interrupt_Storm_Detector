/*
 *
 *
 */
#include <linux/kernel_stat.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
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
#include <linux/kstrtox.h>
#include <linux/preempt.h>
#include <linux/workqueue.h>

#include "irq_detector.h"

#define SAMPLING_INTERVAL	500L /*10 milli second*/
#define MS_TO_NS(x)		(x * 1E6L)
#define MAX_SIZE		32

//#define DEBUG
#define CONFIG_SEQ_READ

struct irq_desc *irq_desc_node;
int irq;
static u64 t1, t2;

/*
 * Manifest of proc files to create
 */
struct irq_diag_file {
	const char *filename;
	int *status;
	const struct proc_ops ops;
};

struct irq_detector_data {
	char				version_id[64];
	uint8_t 			id;
	struct platform_device		*pdev;
	struct mutex			mutex_lock;
	struct proc_dir_entry		*proc_dir;
	struct irq_diag_file		*mproc_files;
	unsigned long			irq_interval_threshold_us;
	atomic_t 			inst_irq_rate;
	void				*virt_addr;
	phys_addr_t			phys_addr;
	int				irq;
	struct irq_desc 		*desc;
	//int 				irq_count;
	//int 				prev_irq_count;
	//unsigned long               	irq_timestamp;
	//unsigned long               	last_irq_timestamp;
	struct hrtimer 			mhr_timer;
	struct task_struct		*irq_poll_thread;
	/* Head for list of IRQ numbers and there is an
	 * individual link lists for each IRQ number.
	 */
	struct list_head		irq_num_list_head;
	struct irq_num_heads_list	*irq_num_heads;
	bool				irq_num_head_list_created;
	/*For debugging single irq num stat*/
	//struct irq_num_statistics_list         *irq_num_statistics_node;
	struct work_struct          	work;
};

int create_list_of_all_irq_numbers(struct irq_detector_data *pirq_data);
u8 cnt = 0;

enum hrtimer_restart read_irq_interval_cb( struct hrtimer *hrtimer )
{
	char check_context;
	
	struct irq_detector_data *priv =
		container_of(hrtimer, struct irq_detector_data, mhr_timer);

	pr_info( "my_hrtimer_callback called (%ld).\n");
	
	check_context = in_interrupt();	
	pr_alert("In func - %s, line - %d, context = %d\n",
		__func__, __LINE__, check_context);

	/* Now 'schedule' our workqueue function to run */
	if (!schedule_work(&priv->work))
		pr_notice("our work's already on the kernel-global workqueue!\n");

	t1 = ktime_get_real_ns();

	hrtimer_forward_now(hrtimer, ktime_set(0, MS_TO_NS(SAMPLING_INTERVAL)));

	return HRTIMER_RESTART;
}

/*
 * work_func() - our workqueue callback function!
 */
static void work_func(struct work_struct *work)
{
	struct irq_detector_data *priv = container_of(work, struct irq_detector_data, work);
	struct irq_num_statistics_list *node_linked_list;
	int irq;
	int ret, cpu_i;
	int tot_irq_count_per_sample = 0;
	struct irq_num_heads_list *ptr;

	t2 = ktime_get_real_ns();

	/*Create list of heads of all IRQ numbers only once.*/
	if(priv->irq_num_head_list_created == 0) {

		priv->irq_num_head_list_created = 1;
		ret = create_list_of_all_irq_numbers(priv);
		if(ret < 0) {
        		pr_err("create list of heads of all IRQ nos. failed\n");
        		goto out;
		}
	}

	/*Iterate through all IRQ descriptors*/
	for_each_irq_desc(irq, priv->desc) {

		if(priv->desc) {
	
		//******************TODO******************//
		//1. Find online CPUs
		//2. Find IRQ count for each CPU
		//****************************************//			
			list_for_each_entry(ptr, &priv->irq_num_list_head, list_of_heads) {

				pr_debug("DBG:list of heads loop, Irq num - %d\n", ptr->irq_num);
				
				if(ptr->irq_num == priv->desc->irq_data.irq) {
					if (desc->kstat_irqs) {
						for_each_online_cpu(cpu_i) {
								if (priv->desc->kstat_irqs) {
								ptr->irq_count_per_cpu[cpu_i] = *per_cpu_ptr(priv->desc->kstat_irqs, cpu_i); 				
								tot_irq_count_per_sample += *per_cpu_ptr(priv->desc->kstat_irqs, cpu_i);
							}			
						}
					}

					ptr->irq_count = tot_irq_count_per_sample;

					if (ptr->irq_prev_count == 0) {
						ptr->irq_prev_count = tot_irq_count_per_sample;
						goto out;	
					}

					node_linked_list =
						kmalloc(sizeof(struct irq_num_statistics_list), GFP_KERNEL);
					if(!node_linked_list) {
						goto out;
					}

					/*Fill the node of list*/
					node_linked_list->irq_num = ptr->irq_num;
					node_linked_list->irq_count = ptr->irq_count;	
					node_linked_list->irq_rate =
								(node_linked_list->irq_count - ptr->irq_prev_count);

					list_add_tail(&node_linked_list->list_node, &ptr->list_of_node);

					ptr->irq_prev_count = tot_irq_count_per_sample;

					break;
				}

			}/*list_for_each_entry*/

			pr_debug("For Irq# - %d, IRQ rate - %d per %d ms\n",
					node_linked_list->irq_num,
					node_linked_list->irq_rate, SAMPLING_INTERVAL);
		} 
	}/*for_each_irq_desc()*/

out:
	pr_alert("In our workq function: %s\n", __func__);
	SHOW_DELTA(t2, t1);
}

#if 0
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
//	for_each_irq_desc(irq, irq_desc_node) {

		if(cnt % 10000) {
			cnt++;
			pr_alert("DBG: In func - %s, Line - %d\n", __func__, __LINE__);
		}

#if 0
		//pr_alert("IRQ name - %s\n", irq_desc_node->name);
		if(irq_desc_node && !(irq_desc_node->irq_count % 1000)) { //1000 -> 5 for debugging

			if(time_before(jiffies, 
				mirq_data->last_irq_timestamp + HZ/10)) {
				pr_alert(" Interrupt storm detected");
			}
			//pr_alert("DBG: In func - %s, Line - %d\n", __func__, __LINE__);
			mirq_data->last_irq_timestamp = jiffies;
                }
#endif
  //      }

	/*if( ) {

	}*/

    }
#endif
    return 0;
}
#endif

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

static int start_irq_rate_calc(struct irq_detector_data *mirq_data)
{
	int ret = 0;
	ktime_t ktime;
	unsigned long delay_in_ms = SAMPLING_INTERVAL;

	if(mirq_data == NULL) {
		ret = -EINVAL;
		goto out;
	}

	/* ktime_set(TIMEOUT_SEC, TIMEOUT_NSEC)*/
	ktime = ktime_set(0, MS_TO_NS(SAMPLING_INTERVAL));

	pr_info("Starting timer to fire in %ldms (%ld)\n", \
					delay_in_ms, jiffies );

	hrtimer_start(&mirq_data->mhr_timer, ktime, HRTIMER_MODE_REL);

out: 
	return ret;
}

static void stop_irq_rate_calc(struct irq_detector_data *mirq_data)
{
	pr_alert("DBG: Stopping HR timer used for IRQ rate calculation\n");

	hrtimer_cancel(&mirq_data->mhr_timer);
}

static int show_irq_cmd(struct seq_file *seq, void *pdata)
{
	unsigned long phys_addr = 0x100;
	unsigned long size = 0x30;
	struct irq_detector_data *pirq_data = pdata;

	unsigned long irq_cnt = kstat_irqs_cpu(152, 0); //IRQ num, CPU#

	seq_printf(seq, "Base(0x%lx) Size(0x%lx)\n", phys_addr, size);
	seq_printf(seq, "IRQ count - %ld\n", irq_cnt);

	//read_irq_data();

	for_each_irq_desc(irq, pirq_data->desc) {
		if(pirq_data->desc) {
			seq_printf(seq, "irq_detect: Linux Irq No. - %d, Hw Irq No. - %lu, Irq name - %s\n",
				pirq_data->desc->irq_data.irq, pirq_data->desc->irq_data.hwirq,
				pirq_data->desc->irq_data.chip->name);
		} 
	}

	return 0;
}

static int irq_diag_open_cmd(struct inode *inode, struct file *file)
{
	/*  */
	struct irq_detector_data *mirq_data;
	int ret;

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
	mirq_data = pde_data(inode);
#else
	mirq_data = PDEV_DATA(inode);
#endif

	pr_alert("DBG: In func - %s\n", __func__);
	ret = single_open(file, show_irq_cmd, mirq_data);

	return ret;
}

static int irq_diag_release_cmd(struct inode *inode, struct file *file)
{
	int res = single_release(inode, file);

	return res;
}

static int parse_number(const char __user *p, size_t count, unsigned int *val)
{
	char buf[40];
	char *end;

	if (count > 39)
		return -EINVAL;

	if (copy_from_user(buf, p, count))
		return -EFAULT;

	buf[count] = 0;
	*val = simple_strtoul(buf, &end, 10);
	if (*end && *end != '\n')
		return -EINVAL;

	return 0;
}

static ssize_t irq_diag_write_cmd(struct file *filep, const char __user *buf,
      size_t count, loff_t *off)
{
	int ret;
	unsigned long n;
	unsigned int irq_cnt = 0;

	struct irq_detector_data *mirq_data;

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
        mirq_data = pde_data(file_inode(filep));
#else
        mirq_data = PDE_DATA(file_inode(filep));
#endif

	char *temp_buf = kzalloc(32, GFP_USER);

	if (!temp_buf)
		return -ENOMEM;

	ret = -EINVAL;
	if (count >= PAGE_SIZE)
		goto out;

	ret = -EFAULT;
	if (copy_from_user(temp_buf, buf, count))
		goto out;

	temp_buf[count-1] = '\0';

	ret = count;
	pr_alert("DBG: String: %s, length - %d\n", temp_buf, count);

	if(!strcmp(temp_buf, "on")) { /*Start IRQ scanning*/
#if 0
		ret = create_list_of_all_irq_numbers(mirq_data);
		if(ret < 0) {
			pr_err("creat list of heads of all IRQ nos. failed\n");
			goto out;
		}
#endif

		start_irq_rate_calc(mirq_data);
	} else if (!strcmp(temp_buf, "off")) { /*Stop IRQ scanning*/
		stop_irq_rate_calc(mirq_data);
	} else if ((*temp_buf > 0) && (*temp_buf <= 65535)) {

		ret = parse_number(buf, count, &irq_cnt);
		if(ret != 0)
			goto out;
	} else {
		pr_alert("DBG: Wrong command\n");
		ret = -EINVAL;
	}

out:
	kfree(temp_buf);
	return ret;
}

static ssize_t irq_diag_read_cmd(struct file *filep, char __user *user_buf, 
		size_t length, loff_t *offset)
{
	char str[13] = "HelloWorld!\n";
	char *pstr;
	ssize_t bytes;

	int len_str = sizeof(str);
	ssize_t ret = len_str;

	struct irq_detector_data *mirq_data;

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
        mirq_data = pde_data(file_inode(filep));
#else
        mirq_data = PDE_DATA(file_inode(filep));
#endif
	bytes = min(len_str, length);

	pstr = str;

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

static int show_irq_stat(struct seq_file *seq, void *pdata)
{
	struct list_head *ptr;
	/*single_open() function assigns seq_file->private by user data*/
	struct irq_detector_data *mirq_data = seq->private;

	struct irq_num_heads_list *ptr_irq_num_head;
	struct irq_num_statistics_list *tmp;

	pr_alert("DBG: In func - %s, line - %d, Version - %s, Id - %d\n",
			__func__, __LINE__, mirq_data->version_id, mirq_data->id);

	list_for_each_entry(ptr_irq_num_head, &mirq_data->irq_num_list_head, list_of_heads) {

		list_for_each_entry(tmp, &ptr_irq_num_head->list_of_node, list_node) {
			seq_printf(seq, "Irq No. - %d, IRQ count - %d, IRQ rate - %d\n",
                               tmp->irq_num, tmp->irq_count, tmp->irq_rate);
		}
		seq_printf(seq,"\n\n\n\n");
	}
	return 0;
}

static int irq_diag_open_stat(struct inode *inode, struct file *file)
{
	struct irq_detector_data *mirq_data;
	int ret;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
	mirq_data = pde_data(inode);
#else
	mirq_data = PDEV_DATA(inode);
#endif
	/*Print is working, to debug pass of data*/
	pr_alert("DBG: In func - %s, id - %d\n", __func__, mirq_data->id);

	ret = single_open(file, show_irq_stat, mirq_data);

	return ret;
}

static int irq_diag_release_stat(struct inode *inode, struct file *file)
{
	int res = single_release(inode, file);

	return res;
}

static ssize_t irq_diag_write_stat(struct file *filep, const char __user *buf,
      size_t count, loff_t *off)
{
	int ret = count;
	
	return ret;
}

static ssize_t irq_diag_read_stat(struct file *filep, char __user *user_buf,
                size_t count, loff_t *offset)
{
	ssize_t bytes = count;
	
	return bytes;
}

static const struct irq_diag_file irq_diag_files[] = {
	{
		.filename	= "irq_diag_cmd",
		.status		= NULL,
		.ops.proc_open	= irq_diag_open_cmd,
#ifndef CONFIG_SEQ_READ
		.ops.proc_read	= irq_diag_read_cmd,
#else
		.ops.proc_read = seq_read,
#endif
		.ops.proc_write	= irq_diag_write_cmd,
		.ops.proc_release = irq_diag_release_cmd,
		.ops.proc_lseek	= default_llseek,
	},
	{
		.filename	= "irq_diag_stat",
		.status		= NULL,
		.ops.proc_open  = irq_diag_open_stat,
#ifndef CONFIG_SEQ_READ
		.ops.proc_read	= irq_diag_read_stat,
#else
		.ops.proc_read  = seq_read,
#endif
		.ops.proc_write	= irq_diag_write_stat,
		.ops.proc_release = irq_diag_release_stat,
		.ops.proc_lseek	= default_llseek,
	},
	/*{

	},*/
};

static int create_proc_entry(struct irq_detector_data *mirq_data)
{
	int i;
	struct irq_diag_file *f;

	if(mirq_data == NULL)
		return -EINVAL;

	mirq_data->proc_dir = proc_mkdir("irq_diag",NULL);
	if(!mirq_data->proc_dir) {
		pr_err("DBG: Error creating proc directory\n");
		return -ENOMEM;
	}

	for (i = 0; i < ARRAY_SIZE(irq_diag_files); i++) {
		f = &mirq_data->mproc_files[i];

		if (!proc_create_data(f->filename, S_IWUSR | S_IRUSR, 
					mirq_data->proc_dir, &f->ops, mirq_data))
			goto enomem;
	}

#if 0
	scnprintf(mirq_data->name, 20, "irq_storm_stat");
	mirq_data->proc_file = proc_create(mirq_data->name, 
			S_IWUSR | S_IRUSR, mirq_data->proc_dir, &procfs_test_pops);
        if (!mirq_data->proc_file) {
                return -ENOMEM;
	}
#endif
	
enomem:
	while (--i >= 0) {
		f = &mirq_data->mproc_files[i];
		remove_proc_entry(f->filename, NULL);
	}

	return 0;
}

static void delete_proc_entry(struct irq_detector_data *mirq_data)
{
	int i;
	struct irq_diag_file *f;

	if(mirq_data == NULL)
		return;

//	remove_proc_entry("irq_storm_stat", mirq_data->proc_dir);
	for (i = 0; i < ARRAY_SIZE(irq_diag_files); i++) {
		f = &mirq_data->mproc_files[i];

		remove_proc_entry(f->filename, NULL);
	}

	remove_proc_entry("irq_diag", NULL);
}

int
create_list_of_all_irq_numbers(struct irq_detector_data *pirq_data)
{
	struct irq_num_heads_list *ptr;
	int irq;
	int index = 0;
	
	/*Iterate through all IRQ descriptors*/
	for_each_irq_desc(irq, pirq_data->desc) {

	if(pirq_data->desc) {
		
		pirq_data->irq_num_heads =
				kzalloc(sizeof(struct irq_num_heads_list),GFP_KERNEL);
		if(!pirq_data->irq_num_heads)
			return -ENOMEM;

		/*Store IRQ number as Key for a node*/
		pirq_data->irq_num_heads->irq_num = pirq_data->desc->irq_data.irq;

		INIT_LIST_HEAD(&pirq_data->irq_num_heads->list_of_node);

		list_add_tail(&pirq_data->irq_num_heads->list_of_heads,
				&pirq_data->irq_num_list_head);
		}
    }
	
	/*Verify created list of heads for each
	 * available IRQ numbers.
	 */	
#ifdef DEBUG	
	list_for_each_entry(ptr, &pirq_data->irq_num_list_head, list_of_heads) {
		/*for debugging only*/
		pr_alert("In func - %s, IRQ# - %d\n", __func__, ptr->irq_num);	
	}
#endif

	return 0;
}

static int irq_detector_probe(struct platform_device *pdev)
{
	struct irq_detector_data *mirq_data;
	struct device *dev = &pdev->dev;
	struct device_node *np;
	int ret = 0;

	if(dev == NULL) {
		ret = -EINVAL;
		goto probe_fail;
	}
	np = pdev->dev.of_node;

	mirq_data = devm_kzalloc(dev, sizeof(*mirq_data), GFP_KERNEL);
        if (!mirq_data)
                return -ENOMEM;
	scnprintf(mirq_data->version_id, 64, "Irq Diag Ver - 1.0");
	mirq_data->id = 55;
	//mirq_data->irq_num_statistics_node =
	//	kzalloc(sizeof(struct irq_num_statistics_list), GFP_KERNEL);
	//if(!mirq_data->irq_num_statistics_node)
	//	return -ENOMEM;

	//mirq_data->irq_timestamp = jiffies;

	mirq_data->mproc_files = irq_diag_files;

	hrtimer_init(&mirq_data->mhr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mirq_data->mhr_timer.function = &read_irq_interval_cb;
	mirq_data->irq_num_head_list_created = 0;
	/*16-03-2024*/
	//INIT_LIST_HEAD(&mirq_data->irq_num_statistics_node->list);
	INIT_LIST_HEAD(&mirq_data->irq_num_list_head);
	
	//create_list_of_all_irq_numbers(mirq_data);

	/* Initialize our workqueue */
	INIT_WORK(&mirq_data->work, work_func);

	platform_set_drvdata(pdev, mirq_data);

	ret = create_proc_entry(mirq_data);
	if(ret < 0) {
		pr_alert("DBG: proc file creation failed!");
		goto probe_fail;
	}

#if 0
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
#endif
	pr_alert("DBG: In function - %s, Line - %d\n", __func__, __LINE__);

probe_fail:
	return ret;
}

static int irq_detector_remove(struct platform_device *pdev)
{
    struct irq_detector_data *mirq_data = platform_get_drvdata(pdev);
    int ret = 0;

	/* Wait for any pending work (queue) to finish*/
    if (cancel_work_sync(&mirq_data->work))
		pr_info("yes, there was indeed some pending work; now done...\n");
	
	hrtimer_cancel(&mirq_data->mhr_timer);
	
	kthread_stop(mirq_data->irq_poll_thread);

	delete_proc_entry(mirq_data);

	/*TODO: Delete all linked lists*/

	if(mirq_data)
		kfree(mirq_data);

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
