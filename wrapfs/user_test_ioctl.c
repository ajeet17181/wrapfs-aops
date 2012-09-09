#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>
#include <errno.h>
#include <linux/wrapfs_ioctl.h>

int main(int argc, char **argv)
{
	int fd, ret = -1;
	char *key = NULL, *salt = NULL, *keycrypt = NULL;
	char keystr[34];
	int keylen = 0;
	if (argc != 3)
		return -1;
	fd = open(argv[1], O_RDONLY);
	key = argv[2];
	if ((key == NULL) || (strlen(key) < 6)) {
		printf("Invalid Key!!\n");
		return 0;
	}
	memset(keystr, 0x00, 34);
	if (memcmp(key, "000000", 6) == 0) {
		memcpy(keystr, "00000000", 8);
	} else {
		salt = calloc(12, sizeof(char));
		strncpy(salt, "$1$", 3);
		strncat(salt, "abcdefgh", 8);
		keycrypt = crypt(key, salt);
		if (!keycrypt) {
			printf("Error : crypt returned NULL\n");
			return -1;
		}
		keylen = strlen(keycrypt);
		strncpy(keystr, keycrypt, keylen);
		/*printf("MD5 key : %s, %d\n", keystr, keylen);*/
		/*ret = ioctl(fd, WRAPFS_IOCTL_SET_KEY, "TestPassword");*/
	}
	ret = ioctl(fd, WRAPFS_IOCTL_SET_KEY, keystr+2);
	if (ret < 0)
		perror("");
	return 0;
}
