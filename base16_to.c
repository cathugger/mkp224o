#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "base16.h"

static const char base16t[16] = {
	'0', '1', '2', '3',
	'4', '5', '6', '7',
	'8', '9', 'A', 'B',
	'C', 'D', 'E', 'F',
};

char *base16_to(char *dst, const u8 *src, size_t slen)
{
	for (size_t i = 0; i < slen; ++i) {
		*dst++ = base16t[src[i] >> 4];
		*dst++ = base16t[src[i] & 15];
	}
	*dst = 0;
	return dst;
}
