// converts src[0:slen] to base64 string
char *base64_to(char *dst,const u8 *src,size_t slen);
// calculates length needed to store data converted to base64
#define BASE64_TO_LEN(l) (((l + 3 - 1) / 3) * 4)
// converts src string from base64
size_t base64_from(u8 *dst,const char *src,size_t slen);
// calculates length needed to store data converted from base
#define BASE64_FROM_LEN(l) ((l) / 4 * 3)
// validates base32 string and optionally stores length of valid data
// returns 1 if whole string is good, 0 if string contains invalid data
int base64_valid(const char *src,size_t *count);
