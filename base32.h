// converts src[0:slen] to base32 string
char *base32_to(char *dst,const u8 *src,size_t slen);
// calculates length needed to store data converted to base32
#define BASE32_TO_LEN(l) (((l) * 8 + 4) / 5)
// converts src string from base32
size_t base32_from(u8 *dst,u8 *dmask,const char *src);
// calculates length needed to store data converted from base32
#define BASE32_FROM_LEN(l) (((l) * 5 + 7) / 8)
// validates base32 string and optionally stores length of valid data
// returns 1 if whole string is good, 0 if string contains invalid data
int base32_valid(const char *src,size_t *count);
