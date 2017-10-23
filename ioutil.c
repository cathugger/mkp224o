#include <stdint.h>
#include <string.h>
#include "types.h"
#include "ioutil.h"
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int writeall(FH fd,const u8 *data,size_t len)
{
	ssize_t wrote;
	while (len) {
		wrote = write(fd,data,len);
		if (wrote == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				continue;
			return -1;
		}
		len -= wrote;
		data += wrote;
	}
	return 0;
}

FH createfile(const char *path,int secret)
{
	int fd;
	do {
		fd = open(path,O_WRONLY | O_CREAT | O_TRUNC,secret ? 0600 : 0666);
		if (fd == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
	} while (0);
	return fd;
}

int closefile(FH fd)
{
	int cret;
	do {
		cret = close(fd);
		if (cret == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
	} while (0);
	return 0;
}

int writetofile(const char *path,const u8 *data,size_t len,int secret)
{
	FH fd = createfile(path,secret);
	int wret = writeall(fd,data,len);
	int cret = closefile(fd);
	if (cret == -1)
		return -1;
	return wret;
}

int createdir(const char *path,int secret)
{
	return mkdir(path,secret ? 0700 : 0777);
}
