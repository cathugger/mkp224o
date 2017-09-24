#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "base32.h"

static const u8 base32f[256] = {
	['a'] =  0, ['b'] =  1, ['c'] =  2, ['d'] =  3,
	['e'] =  4, ['f'] =  5, ['g'] =  6, ['h'] =  7,
	['i'] =  8, ['j'] =  9, ['k'] = 10, ['l'] = 11,
	['m'] = 12, ['n'] = 13, ['o'] = 14, ['p'] = 15,
	['q'] = 16, ['r'] = 17, ['s'] = 18, ['t'] = 19,
	['u'] = 20, ['v'] = 21, ['w'] = 22, ['x'] = 23,
	['y'] = 24, ['z'] = 25, ['2'] = 26, ['3'] = 27,
	['4'] = 28, ['5'] = 29, ['6'] = 30, ['7'] = 31,
};
/*
+--first octet--+-second octet--+--third octet--+--forth octet--+--fifth octet--+
|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
+---------+-----+---+---------+-+-------+-------+-+---------+---+-----+---------+
|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|
+-1.index-+-2.index-+-3.index-+-4.index-+-5.index-+-6.index-+-7.index-+-8.index-+
*/
size_t base32_from(u8 *dst, u8 *dmask, const char *src)
{
	int i, j, k = -1, l;
	u8 mask = 0;
	for (i = 0;;i += 5) {
		j = i/5;
		l = i%8;
		if (!src[j]) {
			if (!l) // workaround: if l==0 mask misses some upper bits
				mask = 0xFF;
			if (k >= 0)
				dst[k] &= mask;
			//printf("dst[k]:%02X mask:%02X l:%d\n", dst[k], (unsigned int)(mask & 0xFF), l);
			*dmask = mask;
			return (size_t)(k + 1);
		}
		k = i/8;
		mask = (0x1F << 3) >> l;
		dst[k] &= ~mask;
		dst[k] |= (base32f[(u8)src[j]] << 3) >> l;
		if (((0x1F << 8) >> (l+5-8)) & 0xFF) {
			mask = ((0x1F << 8) >> (l+5-8)) & 0xFF;
			++k;
			dst[k] &= ~mask;
			dst[k] |= ((base32f[(u8)src[j]] << 8) >> (l+5-8)) & 0xFF;
		}
		//printf("i = %02d, i/8 = %02d, i%8 = %02d, i%8+5-8 = %02d\n", i, i/8, i%8, i%8+5-8);
		//printf("mask0: %02x\n", (0x1F << 3) >> (i%8));
		//printf("mask1: %02x\n", ((0x1F << 8) >> (i%8+5-8)) & 0xFF);
	}
}
