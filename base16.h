// converts src[0:slen] to base16 string
char *base16_to(char *dst,const u8 *src,size_t slen);
// calculates length needed to store data converted to base16
#define BASE16_TO_LEN(l) (((l) * 8 + 3) / 4)
// converts src string from base16
size_t base16_from(u8 *dst,u8 *dmask,const char *src);
// calculates length needed to store data converted from base16
#define BASE16_FROM_LEN(l) (((l) * 4 + 7) / 8)
// validates base16 string and optionally stores length of valid data
// returns 1 if whole string is good, 0 if string contains invalid data
int base16_valid(const char *src,size_t *count);
