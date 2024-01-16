
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>

#define REG_IRQ_NUM             _IOW('a','a',int32_t*)

#define TUNER_CHIP_IRQ_NUM     26

static int fd, fd_irq_counter;
static uint32_t irq_cnt;
uint8_t usr_buf[4];
static int irq_number;

int open_file()
{
	fd = open (DEVNAME, O_RDWR);
	if (fd < 0 )
	{
		printf ("Cannot open SPI device file\n");
                return -1;
	}

	fd_irq_counter = open("/dev/irq_counter_device", O_RDWR);
        if(fd_irq_counter < 0) {
            printf("Cannot open IRQ_CNT device file...\n");
            return -1;
        }

	return 0;
}

int register_irqnum_to_monitor(int fd, int32_t irq_num)
{
	if (ioctl(fd_irq_counter, REG_IRQ_NUM, (int32_t*)&irq_num))
	{
                printf("Failed\n");
                close(fd);
                return -1;
        }

	return 0;
}

int main()
{
	char boot;
	pthread_t tid1;

	open_file();

	pthread_create(&tid1, NULL, read_irq_stat, NULL);

	pthread_join( tid1, NULL);

	close(fd);
}
