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
//#include <irq/internals.h>
#include <linux/of.h>
#include <linux/kthread.h>
#include <linux/sched.h>  
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/completion.h>
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

//static struct platform_device *irq_detector_device;
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
	struct mutex			mlock;
	struct completion		complete;
	spinlock_t			slock;
	struct proc_dir_entry		*proc_dir;
	struct irq_diag_file		*mproc_files;
	struct proc_dir_entry		*proc_subdir;
	struct irq_diag_file		*mproc_param_files;
	unsigned long			irq_interval_threshold_us;
	atomic_t 			inst_irq_rate;
	void				*virt_addr;
	phys_addr_t			phys_addr;
	int				irq;
	struct irq_desc 		*desc;
	struct hrtimer 			mhr_timer;
	struct task_struct		*irq_poll_thread;
	/* Head for list of IRQ numbers and there is an
	 * individual link lists for each IRQ number.
	 */
	struct list_head		irq_num_list_head;
	struct irq_num_heads_list	*irq_num_heads;
	bool				irq_num_head_list_created;
	struct work_struct          	scan_work;
	struct work_struct		notify_work;
	unsigned int			status_flag;
};

int create_list_of_all_irq_numbers(struct irq_detector_data *pirq_data);
u8 cnt = 0;

enum hrtimer_restart read_irq_interval_cb( struct hrtimer *hrtimer )
{
	char check_context;
	
	struct irq_detector_data *priv =
		container_of(hrtimer, struct irq_detector_data, mhr_timer);

	pr_debug( "my_hrtimer_callback called.\n");
	
	check_context = in_interrupt();	
	pr_alert("In func - %s, line - %d, context = %d\n",
		__func__, __LINE__, check_context);

	/* Now 'schedule' our workqueue function to run */
	if (!schedule_work(&priv->scan_work))
		pr_notice("our work's already on the kernel-global workqueue!\n");

	t1 = ktime_get_real_ns();

	hrtimer_forward_now(hrtimer, ktime_set(0, MS_TO_NS(SAMPLING_INTERVAL)));

	return HRTIMER_RESTART;
}

#if 1
static void irq_mon_thread_wake(struct irq_detector_data *priv)
{
	if(priv->irq_poll_thread)
		wake_up_process(priv->irq_poll_thread);
}
#endif

/*
 * iirq_scan_work() - our workqueue callback function!
 */
static void irq_scan_work(struct work_struct *work)
{
	struct irq_detector_data *priv = container_of(work,
				struct irq_detector_data, scan_work);
	struct irq_num_statistics_list *node_linked_list;
	struct irq_num_statistics_list *oldest_node;
	int irq;
	int ret, cpu_i;
	int tot_irq_cnt = 0;
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

		irq_mon_thread_wake(priv);
	}

	/*Iterate through all IRQ descriptors*/
	for_each_irq_desc(irq, priv->desc) {

		if(!priv->desc)
			continue;

		if(!priv->desc->action) //|| irq_desc_is_chained(priv->desc))
			continue;

		/*Scan list of IRQ numbers and fill liked list for each IRQ#*/
		list_for_each_entry(ptr, &priv->irq_num_list_head, list_of_heads) {

			pr_debug("DBG:list of heads loop, Irq num - %d\n", ptr->irq_num);
			//pr_alert("DBG: Line - %d\n", __LINE__);	
			if((ptr->irq_num == priv->desc->irq_data.irq) && priv->desc->kstat_irqs) {
				/*Calculate total irq count*/

				if(mutex_lock_interruptible(&priv->mlock))
					return;
				//pr_alert("DBG: Line - %d\n", __LINE__);	
				for_each_online_cpu(cpu_i) {
					if (priv->desc->kstat_irqs) {
						ptr->irq_count_per_cpu[cpu_i] =
							*per_cpu_ptr(priv->desc->kstat_irqs, cpu_i); 				
						tot_irq_cnt +=
							*per_cpu_ptr(priv->desc->kstat_irqs, cpu_i);
					}			
				}

			if(!tot_irq_cnt) {
				mutex_unlock(&priv->mlock);
				break;
			}

			ptr->irq_count = tot_irq_cnt;
			if (ptr->irq_prev_count == 0) {
				ptr->irq_prev_count = tot_irq_cnt;
				mutex_unlock(&priv->mlock);
				goto out;	
			}
		
			if(ptr->cir_queue_size >= MAX_CIRCULAR_QUEUE_SIZE) {
				oldest_node = list_first_entry(&ptr->list_of_node,
						struct irq_num_statistics_list, list_node);
				list_del(&oldest_node->list_node);
				kfree(oldest_node);
				ptr->cir_queue_size--;
			}
					
			/*TODO: Add a mechanism to add node only if irq occured on this line*/
			//..
			
			node_linked_list =
				kmalloc(sizeof(struct irq_num_statistics_list), GFP_KERNEL);
			if(!node_linked_list) {
				mutex_unlock(&priv->mlock);
				goto out;
			}

			/*Fill the node of list*/
			node_linked_list->irq_num = ptr->irq_num;
			node_linked_list->irq_count = ptr->irq_count;	
			node_linked_list->irq_rate =
						(node_linked_list->irq_count - ptr->irq_prev_count);
			node_linked_list->irq_timestamp = jiffies;
			list_add_tail(&node_linked_list->list_node, &ptr->list_of_node);

			/*Fill max irq rate in each nodes of list of IRQ numbers*/
			if(ptr->max_irq_rate < node_linked_list->irq_rate)
				ptr->max_irq_rate = node_linked_list->irq_rate;

			ptr->irq_prev_count = tot_irq_cnt;
			ptr->cir_queue_size++;
			tot_irq_cnt = 0;

			mutex_unlock(&priv->mlock);
			complete(&priv->complete);
			break;

			}/*if ptr->irq_num == */
		}/*list_for_each_entry*/

		pr_debug("For Irq# - %d, IRQ rate - %d per %ld ms\n",
			node_linked_list->irq_num, node_linked_list->irq_rate, SAMPLING_INTERVAL);
	}/*for_each_irq_desc()*/

out:
	pr_alert("In our workq function: %s\n", __func__);
	SHOW_DELTA(t2, t1);
}

#if 1
/*
 * uevent_notify_work() - workqueue for user space notify work.
 */
static void uevent_notify_work(struct work_struct *work)
{
	struct irq_detector_data *priv = container_of(work, struct irq_detector_data, notify_work);
	struct platform_device *plat_dev = priv->pdev;
	
	char event_string[20];
	char *envp[2] = {event_string, NULL};
	struct kobject *kobj = NULL;

	pr_alert("DBG: In func - %s, line - %d, Version - %s, Id - %d\n",
                        __func__, __LINE__, priv->version_id, priv->id);
	//spin_lock_irqsave(&priv->slock, flags);

	/*Fill environment data to send to user space */
	switch(priv->status_flag) {
	case 1:
		snprintf(event_string, 20, "ERROR_EVENT=IRQ_STORM");
		break;
	case 2: 
		snprintf(event_string, 20, "ERROR_EVENT=XYZ_ERROR");
		break;
	default: 
		break;
	}

	kobj = &plat_dev->dev.kobj;
	if (kobj) {
		envp[1] = NULL;
		pr_alert("Sending event..\n");
		kobject_uevent_env(kobj, KOBJ_CHANGE, envp);
	}

	//spin_unlock_irqrestore(&priv->slock, flags);
}
#endif

static void uevent_notify_func(struct irq_detector_data *priv)
{
        struct platform_device *plat_dev = priv->pdev;
        char event_string[20];
        char *envp[2] = {event_string, NULL};
        struct kobject *kobj = NULL;

        pr_alert("DBG: In func - %s, line - %d, Version - %s, Id - %d\n",
                        __func__, __LINE__, priv->version_id, priv->id);
        //spin_lock_irqsave(&priv->slock, flags);

        /*Fill environment data to send to user space */
        switch(priv->status_flag) {
        case 1:
                snprintf(event_string, 20, "ERROR_EVENT=IRQ_STORM");
                break;
        case 2:
                snprintf(event_string, 20, "ERROR_EVENT=XYZ_ERROR");
                break;
        default:
                break;
        }

        kobj = &plat_dev->dev.kobj;
	//pr_alert("DBG: kobj = %p, kobj->parent = %p\n", kobj, kobj->parent);
	//pr_alert("DBG: kobj name - %s, kobj parent name - %s\n",
	//		kobject_name(kobj), kobject_name(kobj->parent));

	//pr_alert("DBG: kobj = %p\n", kobj);
	//pr_alert("DBG: kobj->parent = %p\n", kobj->parent);
	//pr_alert("DBG: kobj name - %s\n",kobject_name(kobj));
        if (kobj) {
                envp[1] = NULL;
                pr_alert("Sending event..\n");
                kobject_uevent_env(kobj, KOBJ_CHANGE, envp);
        }

        //spin_unlock_irqrestore(&priv->slock, flags);
}

int monitor_irq_storm_thread(void *pv)
{
	//int ret;
	int i = 0;
	int irq;
	//unsigned long temp_timestamp;
	struct irq_detector_data *priv = (struct irq_detector_data *)pv;
	struct irq_num_heads_list *ptr;

	pr_alert("DBG: In func - %s, line - %d, Version - %s, Id - %d\n",
                        __func__, __LINE__, priv->version_id, priv->id);
	//ptr = list_first_entry(&priv->irq_num_list_head, struct irq_num_heads_list, list_of_heads);
	//struct list_head   tmp_irq_num_list_head;
	//tmp_irq_num_list_head  = priv->irq_num_list_head;

	while(!kthread_should_stop()) {
	pr_alert("In IRQ Poll Thread Function %d\n", i++);
	
	msleep(1000);
	wait_for_completion_interruptible(&priv->complete);

	for_each_irq_desc(irq, priv->desc) {

		if(!priv->desc)
			continue;

		if(!priv->desc->action) //|| irq_desc_is_chained(priv->desc))
			continue;

		/*Scan list of IRQ numbers to read IRQ rate*/
		list_for_each_entry(ptr, &priv->irq_num_list_head, list_of_heads) {
		//pr_alert("DBG: In func - %s, line - %d\n", __func__, __LINE__);	
		/*ret = mutex_lock_interruptible(&priv->mlock);
		if(ret)
			return ret;*/
		if(!ptr)
			continue;

		if(ptr->max_irq_rate > 10) {//Change this param as 10 using some CONFIG macro*/
			//pr_alert("IRQ# - %d, IRQ rate - %d\n", ptr->irq_num, ptr->max_irq_rate);
			priv->status_flag = 1;
			//schedule_work(&priv->notify_work);
			uevent_notify_func(priv);
		}

		//mutex_unlock(&priv->mlock);

		}
	}

	reinit_completion(&priv->complete);	
    }
    return 0;
}

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
	int irq;
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
	mirq_data = (struct irq_detector_data *)pde_data(inode);
#else
	mirq_data = (struct irq_detector_data *)PDE_DATA(inode);
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
	unsigned int irq_cnt = 0;
	char *temp_buf;
	struct irq_detector_data *mirq_data;

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
        mirq_data = pde_data(file_inode(filep));
#else
        mirq_data = PDE_DATA(file_inode(filep));
#endif

	temp_buf = kzalloc(32, GFP_USER);

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
	pr_alert("DBG: String: %s, length - %ld\n", temp_buf, count);

	if(!strcmp(temp_buf, "on")) { /*Start IRQ scanning*/

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

#ifndef CONFIG_SEQ_READ
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
	bytes = min((size_t)len_str, length);

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
			pr_info("DBG: length - %ld, bytes - %lu, *offset - %llu\n",
								length, bytes, *offset);
		}
	}

	return bytes;
}
#endif

static int show_irq_stat(struct seq_file *seq, void *pdata)
{
	/*single_open() function assigns seq_file->private by user data*/
	struct irq_detector_data *mirq_data = seq->private;

	struct irq_num_heads_list *ptr_irq_num_head;
	struct irq_num_statistics_list *pos, *tmp;
	bool header = 1;

	pr_alert("DBG: In func - %s, line - %d, Version - %s, Id - %d\n",
			__func__, __LINE__, mirq_data->version_id, mirq_data->id);

	list_for_each_entry(ptr_irq_num_head, &mirq_data->irq_num_list_head, list_of_heads) {
		list_for_each_entry_safe(pos, tmp, &ptr_irq_num_head->list_of_node, list_node) {

			if(header) {
				header = 0;
				seq_printf(seq, "IRQ No. 	Time Stamp(ms)       IRQ Count 	      IRQ Rate/500ms\n");
				seq_printf(seq, "-------------------------------------------------------------------\n");
			}

			if(ptr_irq_num_head->irq_num == pos->irq_num)
				seq_printf(seq, "%4d %20u %20d %20d\n", pos->irq_num,
							jiffies_to_msecs(pos->irq_timestamp), 
							pos->irq_count, pos->irq_rate);
		}

		header = 1;
		if(ptr_irq_num_head->irq_num == pos->irq_num)
			seq_printf(seq,"\n\n");
	}

	return 0;
}

static int irq_diag_open_stat(struct inode *inode, struct file *file)
{
	struct irq_detector_data *mirq_data;
	int ret;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
	mirq_data = (struct irq_detector_data *)pde_data(inode);
#else
	mirq_data = (struct irq_detector_data *)PDE_DATA(inode);
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

static int show_irq_threshold(struct seq_file *seq, void *pdata)
{
	return 0;
}

static int irq_diag_open_threshold(struct inode *inode, struct file *file)
{
        struct irq_detector_data *mirq_data;
        int ret;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
        mirq_data = (struct irq_detector_data *)pde_data(inode);
#else
        mirq_data = (struct irq_detector_data *)PDE_DATA(inode);
#endif
        /*Print is working, to debug pass of data*/
        pr_alert("DBG: In func - %s, id - %d\n", __func__, mirq_data->id);

        ret = single_open(file, show_irq_threshold, mirq_data);

        return ret;
}

static int irq_diag_release_threshold(struct inode *inode, struct file *file)
{
        int res = single_release(inode, file);

        return res;
}

static ssize_t irq_diag_write_threshold(struct file *filep, const char __user *buf,
      size_t count, loff_t *off)
{
        int ret = count;

        return ret;
}

static int show_irq_interval(struct seq_file *seq, void *pdata)
{

	return 0;
}

static int irq_diag_open_interval(struct inode *inode, struct file *file)
{
        struct irq_detector_data *mirq_data;
        int ret;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
        mirq_data = (struct irq_detector_data *)pde_data(inode);
#else
        mirq_data = (struct irq_detector_data *)PDE_DATA(inode);
#endif
        /*Print is working, to debug pass of data*/
        pr_alert("DBG: In func - %s, id - %d\n", __func__, mirq_data->id);

        ret = single_open(file, show_irq_interval, mirq_data);

        return ret;
}

static int irq_diag_release_interval(struct inode *inode, struct file *file)
{
        int res = single_release(inode, file);

        return res;
}

static ssize_t irq_diag_write_interval(struct file *filep, const char __user *buf,
      size_t count, loff_t *off)
{
        int ret = count;

        return ret;
}

static int show_irq_cirq_nodes(struct seq_file *seq, void *pdata)
{

        return 0;
}

static int irq_diag_open_cirq_nodes(struct inode *inode, struct file *file)
{
        struct irq_detector_data *mirq_data;
        int ret;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0))
        mirq_data = (struct irq_detector_data *)pde_data(inode);
#else
        mirq_data = (struct irq_detector_data *)PDE_DATA(inode);
#endif
        /*Print is working, to debug pass of data*/
        pr_alert("DBG: In func - %s, id - %d\n", __func__, mirq_data->id);

        ret = single_open(file, show_irq_cirq_nodes, mirq_data);

        return ret;
}

static int irq_diag_release_cirq_nodes(struct inode *inode, struct file *file)
{
        int res = single_release(inode, file);

        return res;
}

static ssize_t irq_diag_write_cirq_nodes(struct file *filep, const char __user *buf,
      size_t count, loff_t *off)
{
        int ret = count;

        return ret;
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
		.ops.proc_read	= irq_diag_read_cmd,
#else
		.ops.proc_read  = seq_read,
#endif
		.ops.proc_write	= irq_diag_write_stat,
		.ops.proc_release = irq_diag_release_stat,
		.ops.proc_lseek	= default_llseek,
	},
};

static const struct irq_diag_file irq_diag_param_files[] = {
	{
		.filename       = "IRQ_STORM_THRESHOLD",
                .status         = NULL,
                .ops.proc_open  = irq_diag_open_threshold,
#ifndef CONFIG_SEQ_READ
                .ops.proc_read  = irq_diag_read_cmd,
#else
                .ops.proc_read  = seq_read,
#endif
                .ops.proc_write = irq_diag_write_threshold,
                .ops.proc_release = irq_diag_release_threshold,
                .ops.proc_lseek = default_llseek,
	},

	{
                .filename       = "SAMPLING_INTERVAL",
                .status         = NULL,
                .ops.proc_open  = irq_diag_open_interval,
#ifndef CONFIG_SEQ_READ
                .ops.proc_read  = irq_diag_read_cmd,
#else
                .ops.proc_read  = seq_read,
#endif
                .ops.proc_write = irq_diag_write_interval,
                .ops.proc_release = irq_diag_release_interval,
                .ops.proc_lseek = default_llseek,
        },

	{
                .filename       = "CIRCULAR_QUEUE_NODES",
                .status         = NULL,
                .ops.proc_open  = irq_diag_open_cirq_nodes,
#ifndef CONFIG_SEQ_READ
                .ops.proc_read  = irq_diag_read_cmd,
#else
                .ops.proc_read  = seq_read,
#endif
                .ops.proc_write = irq_diag_write_cirq_nodes,
                .ops.proc_release = irq_diag_release_cirq_nodes,
                .ops.proc_lseek = default_llseek,
        },
};

static int create_proc_entry(struct irq_detector_data *mirq_data)
{
	int i, j;
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

	mirq_data->proc_subdir = proc_mkdir("irq_diag_param", mirq_data->proc_dir);
        if(!mirq_data->proc_subdir) {
                pr_err("DBG: Error creating proc directory\n");
                return -ENOMEM;
        }

        for (j = 0; j < ARRAY_SIZE(irq_diag_param_files); j++) {
                f = &mirq_data->mproc_param_files[j];

                if (!proc_create_data(f->filename, S_IWUSR | S_IRUSR, 
                                        mirq_data->proc_subdir, &f->ops, mirq_data))
                        goto enomem_subdir;
        }	
enomem_subdir:
	while (--j >= 0) {
		f = &mirq_data->mproc_param_files[j];
		remove_proc_entry(f->filename, NULL);
	}

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

	/*TODO*/
	/*Remove param files and subdir*/
}

int
create_list_of_all_irq_numbers(struct irq_detector_data *pirq_data)
{
	int irq;
	
	/*Iterate through all IRQ descriptors*/
	for_each_irq_desc(irq, pirq_data->desc) {

		if(!pirq_data->desc)
			continue;
		pirq_data->irq_num_heads =
				kzalloc(sizeof(struct irq_num_heads_list),GFP_KERNEL);
		if(!pirq_data->irq_num_heads)
			return -ENOMEM;

		/*Store IRQ number as Key for a node*/
		pirq_data->irq_num_heads->irq_num = pirq_data->desc->irq_data.irq;
		pirq_data->irq_num_heads->cir_queue_size = 0;
		pirq_data->irq_num_heads->max_irq_rate = 0;

		INIT_LIST_HEAD(&pirq_data->irq_num_heads->list_of_node);

		list_add_tail(&pirq_data->irq_num_heads->list_of_heads,
				&pirq_data->irq_num_list_head);
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

	pr_alert("DBG: In function - %s, Line - %d\n", __func__, __LINE__);

	if(dev == NULL) {
		ret = -EINVAL;
		goto probe_fail;
	}
	np = pdev->dev.of_node;
	//pdev->dev.kobj.parent = NULL;

	mirq_data = devm_kzalloc(dev, sizeof(*mirq_data), GFP_KERNEL);
        if (!mirq_data)
                return -ENOMEM;
	scnprintf(mirq_data->version_id, 64, "Irq Diag Ver - 1.0");
	mirq_data->id = 55;

	/*set platdevice to driver data*/
	mirq_data->pdev = pdev;

	mirq_data->mproc_files = (struct irq_diag_file *)irq_diag_files;
	mirq_data->mproc_param_files = (struct irq_diag_file *)irq_diag_param_files;

	hrtimer_init(&mirq_data->mhr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	mirq_data->mhr_timer.function = &read_irq_interval_cb;
	mirq_data->irq_num_head_list_created = 0;
	
	INIT_LIST_HEAD(&mirq_data->irq_num_list_head);
	
	/* Initialize irq scan workqueue */
	INIT_WORK(&mirq_data->scan_work, irq_scan_work);

	/*Initialize uevent notify workqueue*/
	INIT_WORK(&mirq_data->notify_work, uevent_notify_work);

	platform_set_drvdata(pdev, mirq_data);
	/* */

	ret = create_proc_entry(mirq_data);
	if(ret < 0) {
		pr_alert("DBG: proc file creation failed!");
		goto probe_fail;
	}

	mutex_init(&mirq_data->mlock);
	init_completion(&mirq_data->complete);
	spin_lock_init(&mirq_data->slock);

	mirq_data->irq_poll_thread = kthread_create(monitor_irq_storm_thread, 
					mirq_data, "Irq Poll Thread");
	if (IS_ERR(mirq_data->irq_poll_thread)) {
		pr_err("Failed to create kthread\n");
		goto probe_fail;
	}

        /*if(mirq_data->irq_poll_thread)
            wake_up_process(mirq_data->irq_poll_thread);*/

	pr_alert("DBG: In function - %s, Line - %d\n", __func__, __LINE__);

probe_fail:
	return ret;
}

static int irq_detector_remove(struct platform_device *pdev)
{
	struct irq_detector_data *mirq_data = platform_get_drvdata(pdev);
	int ret = 0;

	/* Wait for any pending work (queue) to finish*/
	if (cancel_work_sync(&mirq_data->scan_work))
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
MODULE_DEVICE_TABLE(of, irq_detector_of_match_table);

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
	
	.probe = irq_detector_probe,
	.remove = irq_detector_remove,
	.driver = {
		.name = "irq_detector",
		.owner = THIS_MODULE,
		.of_match_table = irq_detector_of_match_table,
		.pm = &devicemodel_pm_ops,
	}
};

module_platform_driver(irq_detector_driver);

#if 0
static struct platform_device irq_detector_device = {
	.name = "irq_detector",
	.id = -1,
};
#endif

#if 0
static int __init irq_detector_init(void)
{
	/*if (platform_device_register(&irq_detector_device))
                pr_info("IRQ_DETECTOR: failed to register device\n");

	return 0;*/
	int error;

	irq_detector_device = platform_device_alloc("irq_detector", -1);
	if (!irq_detector_device)
		error = -ENOMEM;

	error = platform_device_add(irq_detector_device);

	return error;
}
device_initcall(irq_detector_init);
#endif

MODULE_AUTHOR("Mir Faisal <mirfaisalfos@gmail.com>");
MODULE_DESCRIPTION("IRQ Detector");
MODULE_LICENSE("GPL");
