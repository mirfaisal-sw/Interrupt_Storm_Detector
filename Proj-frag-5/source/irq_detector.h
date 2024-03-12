
/* */
#ifndef __IRQ_DETECTOR_H
#define __IRQ_DETECTOR_H

#include <linux/list.h>

#define DEBUG_IRQ_NUM_UNDER_TEST		1U
#define MAX_CPU		8U

#define SHOW_DELTA(later, earlier)      do {    \
        if (time_after((unsigned long)later, (unsigned long)earlier)) { \
            s64 delta_ns = ktime_to_ns(ktime_sub(later, earlier));      \
        pr_info("delta: %lld ns", delta_ns);       \
                if (delta_ns/1000 >= 1)                    \
                        pr_cont(" (~ %lld us", delta_ns/1000);   \
                if (delta_ns/1000000 >= 1)                \
                        pr_cont(" ~ %lld ms", delta_ns/1000000); \
                if (delta_ns/1000 >= 1)                  \
                        pr_cont(")\n");                         \
    } else  \
        pr_warn("SHOW_DELTA(): *invalid* earlier > later? (check order of params)\n");  \
} while (0)

/*Create one more list node, so that it can store pointer to 
 * array of IRQ number link list.
 * Each node will contain pointer to another link list having 
 * array of IRQ statistics per sample. 
 */

//struct irq_num_array_list { ...};

/*IRQ statistics node for an IRQ number,and its address will be
 * embedded in above list node.
 */
struct irq_num_statistics_list {

        struct list_head	list;
        int 			irq_num;
	int			irq_count_per_cpu[MAX_CPU];
	int			irq_prev_count;
        int 			irq_count;
        int			irq_rate;
	unsigned long		last_irq_timestamp;
	unsigned long		irq_timestamp;
};

#endif /* __IRQ_DETECTOR_H */
