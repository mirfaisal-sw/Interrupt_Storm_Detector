
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>

/* Meta Information */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Johannes 4 GNU/Linux");
MODULE_DESCRIPTION("Demonstration for lists in the kernel");

struct my_data {
	struct list_head list;
	char text[64];
};

LIST_HEAD(my_list);

/**
 * @brief This function is called, when the module is loaded into the kernel
 */
static int __init my_init(void) {
	struct my_data *tmp, *next;
	struct list_head *ptr;

	printk("mylist - Hello, Kernel!\n");

	/* Let's create a list with three elements */
	tmp = kmalloc(sizeof(struct my_data), GFP_KERNEL);

	INIT_LIST_HEAD(&tmp->list);
	strcpy(tmp->text, "Hello World");
	list_add_tail(&tmp->list, &my_list);

	tmp = kmalloc(sizeof(struct my_data), GFP_KERNEL);
	strcpy(tmp->text, "Second Element");
	list_add_tail(&tmp->list, &my_list);

	tmp = kmalloc(sizeof(struct my_data), GFP_KERNEL);
	strcpy(tmp->text, "and the last element");
	list_add_tail(&tmp->list, &my_list);

	list_for_each_prev(ptr, &my_list) {
		tmp = list_entry(ptr, struct my_data, list);
		printk("mylist - Element text: %s\n", tmp->text);
	}

	/* Free memory */
	list_for_each_entry_safe(tmp, next, &my_list, list) {
		list_del(&tmp->list);
		kfree(tmp);
	}
	printk("mylist - Freeing memory done!\n");

	return 0;
}

/**
 * @brief This function is called, when the module is removed from the kernel
 */
static void __exit my_exit(void) {
	printk("mylist - Goodbye, Kernel\n");
}

module_init(my_init);
module_exit(my_exit);

