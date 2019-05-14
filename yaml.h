extern void yamlout_init(void);
extern void yamlout_clean(void);
extern void yamlout_writekeys(const char *hostname,const u8 *formated_public,const u8 *formated_secret);
extern int yamlin_parseandcreate(FILE *fin,char *sname,const char *hostname);
