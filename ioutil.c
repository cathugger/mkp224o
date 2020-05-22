#include <stdint.h>
#include <string.h>
#include "types.h"
#include "ioutil.h"

#ifndef _WIN32

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
		len -= (size_t) wrote;
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

int createdir(const char *path,int secret)
{
	return mkdir(path,secret ? 0700 : 0777);
}

#else

int writeall(FH fd,const u8 *data,size_t len)
{
	DWORD wrote;
	BOOL success;
	while (len) {
		success = WriteFile(fd,data,
			len <= (DWORD)-1 ? (DWORD)len : (DWORD)-1,&wrote,0);
		if (!success)
			return -1;
		data += wrote;
		if (len >= wrote)
			len -= wrote;
		else
			len = 0;
	}
	return 0;
}

FH createfile(const char *path,int secret)
{
	// XXX no support for non-ascii chars
	// XXX don't know how to handle secret argument
	(void) secret;
	return CreateFileA(path,GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);
}

int closefile(FH fd)
{
	return CloseHandle(fd) ? 0 : -1;
}

int createdir(const char *path,int secret)
{
	// XXX don't know how to handle secret argument
	(void) secret;
	return CreateDirectoryA(path,0) ? 0 : -1;
}

#endif

int writetofile(const char *path,const u8 *data,size_t len,int secret)
{
	FH fd = createfile(path,secret);
	int wret = writeall(fd,data,len);
	int cret = closefile(fd);
	if (cret == -1)
		return -1;
	return wret;
}
