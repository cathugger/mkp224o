#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "base16.h"

static const u8 base16f[256] = {
	['0'] =  0, ['1'] =  1, ['2'] =  2, ['3'] =  3,
	['4'] =  4, ['5'] =  5, ['6'] =  6, ['7'] =  7,
	['8'] =  8, ['9'] =  9, ['A'] = 10, ['B'] = 11,
	['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
	                        ['a'] = 10, ['b'] = 11,
	['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15,
};

size_t base16_from(u8 *dst, u8 *dmask, const char *src)
{
	int i, j, k = -1, l;
	u8 mask = 0;
	for (i = 0;;i += 4) {
		j = i/4;
		l = i%8;
		if (!src[j]) {
			if (!l)
				mask = 0xFF;
			if (k >= 0)
				dst[k] &= mask;
			*dmask = mask;
			return (size_t)(k+1);
		}
		k = i/8;
		mask = (0x0F << 4) >> l;
		dst[k] &= ~mask;
		dst[k] |= (base16f[(u8)src[j]] << 4) >> l;
	}
}
