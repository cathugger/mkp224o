#include <stdint.h>
#include <string.h>
#include "types.h"
#include "ioutil.h"
#include "vec.h"
#include <stdio.h>

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
		if (fd < 0) {
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
		if (cret < 0) {
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

int syncwrite(const char *filename,int secret,const u8 *data,size_t datalen)
{
	//fprintf(stderr,"filename = %s\n",filename);

	VEC_STRUCT(,char) tmpname;
	size_t fnlen = strlen(filename);
	VEC_INIT(tmpname);
	VEC_ADDN(tmpname,fnlen + 4 /* ".tmp" */ + 1 /* "\0" */);
	memcpy(&VEC_BUF(tmpname,0),filename,fnlen);
	strcpy(&VEC_BUF(tmpname,fnlen),".tmp");
	const char *tmpnamestr = &VEC_BUF(tmpname,0);

	//fprintf(stderr,"tmpnamestr = %s\n",tmpnamestr);

	FH f = createfile(tmpnamestr,secret);
	if (f == FH_invalid)
		return -1;

	if (writeall(f,data,datalen) < 0) {
		closefile(f);
		remove(tmpnamestr);
		return -1;
	}

	int sret;
	do {
		sret = fsync(f);
		if (sret < 0) {
			if (errno == EINTR)
				continue;

			closefile(f);
			remove(tmpnamestr);
			return -1;
		}
	} while (0);

	if (closefile(f) < 0) {
		remove(tmpnamestr);
		return -1;
	}

	if (rename(tmpnamestr,filename) < 0) {
		remove(tmpnamestr);
		return -1;
	}

	VEC_STRUCT(,char) dirname;
	const char *dirnamestr;

	for (ssize_t x = ((ssize_t)fnlen) - 1;x >= 0;--x) {
		if (filename[x] == '/') {
			if (x)
				--x;
			++x;
			VEC_INIT(dirname);
			VEC_ADDN(dirname,x + 1);
			memcpy(&VEC_BUF(dirname,0),filename,x);
			VEC_BUF(dirname,x) = '\0';
			dirnamestr = &VEC_BUF(dirname,0);
			goto foundslash;
		}
	}
	/* not found slash, fall back to "." */
	dirnamestr = ".";

foundslash:
	//fprintf(stderr,"dirnamestr = %s\n",dirnamestr);
	;

	int dirf;
	do {
		dirf = open(dirnamestr,O_RDONLY);
		if (dirf < 0) {
			if (errno == EINTR)
				continue;

			// failed for non-eintr reasons
			goto skipdsync; // don't really care enough
		}
	} while (0);

	do {
		sret = fsync(dirf);
		if (sret < 0) {
			if (errno == EINTR)
				continue;

			// failed for non-eintr reasons
			break; // don't care
		}
	} while (0);

	(void) closefile(dirf); // don't care

skipdsync:

	return 0;
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



int syncwrite(const char *filename,int secret,const char *data,size_t datalen)
{
	VEC_STRUCT(,char) tmpname;
	size_t fnlen = strlen(filename);
	VEC_INIT(tmpname);
	VEC_ADDN(tmpname,fnlen + 4 /* ".tmp" */ + 1 /* "\0" */);
	memcpy(&VEC_BUF(tmpname,0),filename,fnlen);
	strcpy(&VEC_BUF(tmpname,fnlen),".tmp");
	const char *tmpnamestr = &VEC_BUF(tmpname,0);

	FH f = createfile(tmpnamestr,secret)
	if (f == FH_invalid)
		return -1;

	if (writeall(f,data,datalen) < 0) {
		closefile(f);
		remove(tmpnamestr);
		return -1;
	}

	if (FlushFileBuffers(f) == 0) {
		closefile(f);
		remove(tmpnamestr);
		return -1;
	}

	if (closefile(f) < 0) {
		remove(tmpnamestr);
		return -1;
	}

	if (MoveFileA(tmpnamestr,filename) == 0) {
		remove(tmpnamestr);
		return -1;
	}

	// can't fsync parent dir on windows so just end here

	return 0;
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
