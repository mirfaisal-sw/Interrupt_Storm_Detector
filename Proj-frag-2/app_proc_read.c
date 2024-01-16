

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define READ_CHUNK_SIZE		4 /*4 Bytes*/

char buff[1024];
int bytes_count;

int main(int argc, char *argv[])
{
	int fd;
	int i, read_chunk_count, read_frag_count, n;
	
	printf("Usage: ./app_read  [no. of bytes to read]\n");

	if( argc == 2 ) {
		bytes_count = atoi(argv[1]);  /*atoi = ascii to int */
		printf("No. of bytes to read - %d\n", bytes_count);
	}
	else if( argc > 2 ) {
		printf("Too many arguments supplied.\n");
	}
	else {
		printf("One argument expected.\n");
	}

	fd = open("/proc/test_procfs_rw", O_RDWR, S_IRUSR);

	/*Read 4 bytes in one go*/
	read_chunk_count = bytes_count / READ_CHUNK_SIZE;
	read_frag_count = bytes_count % READ_CHUNK_SIZE;

	for(i = 0; i< read_chunk_count; i++) 
	{
		n = read(fd, buff, READ_CHUNK_SIZE);
		buff[4] = '\0';
		printf("APP Log: n - %d, buff = %s\n", n, buff);

		memset(buff, 0, 4);
	}

	if (read_frag_count != 0) {

		for(i = 0; i< read_frag_count; i++) 
		{
			n = read(fd, buff, 1);
			printf("APP Log: n - %d, buff = %c\n", n, *buff);
		}
	}

	return 0;

}


