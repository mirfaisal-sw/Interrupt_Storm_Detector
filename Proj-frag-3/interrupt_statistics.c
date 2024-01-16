#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/uaccess.h>

static void interrupt_cnt = 0;
dev_t dev = 0;
static struct class *dev_class;
static struct cdev interrupt_cnt_cdev;
 
static int __init interrupt_checker_init(void);
static void __exit interrupt_checker_exit(void);


struct my_interrupt{
	

};

/*******************************************************
* Drivers' Helper Function                             *
*******************************************************/
static unsigned int interrupt_cnt_get_irq_statistics(unsigned int irq_num, int cpu)
{
	unsigned int irq_count = 0;
	
	irq_count = kstat_irqs_cpu(irq_num,cpu);

	return irq_count;

}

/*************** Driver functions **********************/
static int interrupt_cnt_open(struct inode *inode, struct file *file);
static int interrupt_cnt_release(struct inode *inode, struct file *file);
static ssize_t interrupt_cnt_read(struct file *filp, 
                char __user *buf, size_t len,loff_t * off);
static ssize_t interrupt_cnt_write(struct file *filp, 
                const char *buf, size_t len, loff_t * off);
static long interrupt_cnt_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
/******************************************************/

/*File operation structure "fops"*/
static struct file_operations interrupt_cnt_fops =
{
  .owner          = THIS_MODULE,
  .read           = interrupt_cnt_read,
  .write          = interrupt_cnt_write,
  .open           = interrupt_cnt_open,
  .release        = interrupt_cnt_release,
  .unlocked_ioctl = interrupt_cnt_ioctl,
};


static int interrupt_cnt_open(struct inode *inode, struct file *file)
{

}

static int interrupt_cnt_release(struct inode *inode, struct file *file)
{
	  
}

static ssize_t interrupt_cnt_read(struct file *filp, char __user *buf, size_t len,loff_t * off)
{
	if( copy_to_user(buf, &gpio_state, len) > 0){
   	
		 pr_err("ERROR: Not all the bytes have been copied to user\n");
  	}
}

static ssize_t interrupt_cnt_write(struct file *filp, const char *buf, size_t len, loff_t * off)
{
	if( copy_from_user( rec_buf, buf, len ) > 0) {
    
		pr_err("ERROR: Not all the bytes have been copied from user\n");
	}
  
        pr_info("Write Function : GPIO_10 Set = %c\n", rec_buf[0]);
}

static long interrupt_cnt_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	kstat_irqs_cpu();	

	if (cmd == REG_CURRENT_TASK)
	{
        	printk(KERN_INFO "REG_CURRENT_TASK\n");
        	task = get_current();
        	signum = SIGMIR;
    	}

	return 0;

}

static int __init interrupt_checker_init(void)
{
	/*Allocating Major number*/
	if((alloc_chrdev_region(&dev, 0, 1, "gpio_dev")) <0){
    		pr_err("Cannot allocate major number\n");
    		goto r_unreg;
  	}

	pr_info("Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

  	/*Creating cdev structure*/
  	cdev_init(&gpio_cdev,&interrupt_cnt_fops);

  	/*Adding character device to the system*/
  	if((cdev_add(&gpio_cdev,dev,1)) < 0){
    		pr_err("Cannot add the device to the system\n");
    		goto r_del;
  	}

  	/*Creating struct class*/
  	if((dev_class = class_create(THIS_MODULE,"gpio_class")) == NULL){
    		pr_err("Cannot create the struct class\n");
    		goto r_class;
  	}

	/*Creating device*/
	if((device_create(dev_class,NULL,dev,NULL,"gpio_device")) == NULL){
    		pr_err( "Cannot create the Device \n");
    		goto r_device;
  	}
        
	r_device:
  		device_destroy(dev_class,dev);
	r_class:
  		class_destroy(dev_class);
	r_del:
  		cdev_del(&gpio_cdev);
	r_unreg:
 	        unregister_chrdev_region(dev,1);
  
  	return -1;

}

static void __exit interrupt_checker_exit(void)
{


}


module_init(interrupt_checker_init);
module_exit(interrupt_checker_exit);

MODULE_DESCRIPTION("This module counts interrupt occured");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("mirfaisalece@gmail.com");
