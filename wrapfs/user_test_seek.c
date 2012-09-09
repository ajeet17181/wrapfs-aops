#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>


int main(int argc, char **argv)
{
	//printk("------------ Start -----------\n");
	char buf[10000] = {0x00,};
	//int fd = open("/mnt/wrapfs/Documentation/filesystems/bfs.txt", O_RDONLY);
	int fd = open(argv[1], O_RDONLY);
	int fd1 = open(argv[2], O_RDWR);
	lseek(fd1, 20, SEEK_END);
	//int fd1 = open("/mnt/wrapfs/output1", O_RDWR | O_CREAT);
	read(fd, buf, 5000);
	write(fd1, buf, 5000);
	close(fd);
	close(fd1);
	//printf("Buffer : %s\n", buf);
	//printk("------------ End -----------\n");
	return 0;
}
