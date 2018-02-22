
#ifndef _WIN32

typedef int FH;
#define FH_invalid -1

#else

#define UNICODE 1
#include <windows.h>
typedef HANDLE FH;
#define FH_invalid INVALID_HANDLE_VALUE

#endif

FH createfile(const char *path,int secret);
int closefile(FH fd);
int writeall(FH,const u8 *data,size_t len);
int writetofile(const char *path,const u8 *data,size_t len,int secret);
int createdir(const char *path,int secret);
