typedef int FH;
#define FH_invalid -1

FH createfile(const char *path,int secret);
int closefile(FH fd);
int writeall(FH,const u8 *data,size_t len);
int writetofile(const char *path,const u8 *data,size_t len,int secret);
int createdir(const char *path,int secret);
