extern void yamlout_init(void);
extern void yamlout_clean(void);
extern void yamlout_writekeys(
	const char *hostname,const u8 *publickey,const u8 *secretkey,int rawkeys);
extern int yamlin_parseandcreate(
	FILE *fin,char *sname,const char *hostname,int rawkeys);
