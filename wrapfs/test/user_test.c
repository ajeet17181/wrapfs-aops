#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/klog.h>
#include <string.h>

int do_syslog(char *msg)
{
	return klogctl(10, msg, strlen(msg));
}

int main(int argc, char **argv)
{
	//printk("------------ Start -----------\n");
	do_syslog("------------ Start -----------\n");
	char buf[1000] = {0x00,};
	//int fd = open("/mnt/wrapfs/Documentation/filesystems/bfs.txt", O_RDONLY);
	int fd = open(argv[1], O_RDONLY);
	int fd1 = open("/mnt/wrapfs/output", O_RDWR);
	read(fd, buf, 999);
	write(fd1, buf, 999);
	//printk("------------ End -----------\n");
	do_syslog("------------ End -----------\n");
	return 0;
}
