#include <sodium/randombytes.h>

static inline int randombytes_wrap(unsigned char *b,size_t l)
{
	randombytes(b,l);
	return 0;
}
#define randombytes randombytes_wrap
