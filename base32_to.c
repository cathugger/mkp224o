#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "base32.h"

static const char base32t[32] = {
	'a', 'b', 'c', 'd', // 0
	'e', 'f', 'g', 'h', // 1
	'i', 'j', 'k', 'l', // 2
	'm', 'n', 'o', 'p', // 3
	'q', 'r', 's', 't', // 4
	'u', 'v', 'w', 'x', // 5
	'y', 'z', '2', '3', // 6
	'4', '5', '6', '7', // 7
};
/*
+--first octet--+-second octet--+--third octet--+--forth octet--+--fifth octet--+
|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
+---------+-----+---+---------+-+-------+-------+-+---------+---+-----+---------+
|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|
+-1.index-+-2.index-+-3.index-+-4.index-+-5.index-+-6.index-+-7.index-+-8.index-+
*/
// masks:
// 0xFF 0x7F 0x3F 0x1F 0x0F 0x07 0x03 0x01
//  255  127  63    31   15   7     3    1
char *base32_to(char *dst, const u8 *src, size_t slen)
{
	//printf("slen = %d\n", slen);
	//printhex(base32t, 32);
	//printhex(base32f, 256);
	// base32 eats in 5bit pieces;
	// closest we can provide is 40, which is 5 bytes
	size_t i;
	for (i = 0; i + 4 < slen; i += 5) {
		//printf("ei!\n");
		//char *od = dst;
		*dst++ = base32t[src[i+0] >> 3];
		*dst++ = base32t[((src[i+0] & 7) << 2) | (src[i+1] >> 6)];
		*dst++ = base32t[(src[i+1] >> 1) & 31];
		*dst++ = base32t[((src[i+1] & 1) << 4) | (src[i+2] >> 4)];
		*dst++ = base32t[((src[i+2] & 15) << 1) | (src[i+3] >> 7)];
		*dst++ = base32t[((src[i+3]) >> 2) & 31];
		*dst++ = base32t[((src[i+3] & 3) << 3) | (src[i+4] >> 5)];
		*dst++ = base32t[src[i+4] & 31];
		//printhex(od, 8);
	}
	//char *od = dst;
	if (i < slen) {
		//printf("oi!0\n");
		*dst++ = base32t[src[i+0] >> 3];
		if (i + 1 < slen) {
			//printf("oi!1\n");
			*dst++ = base32t[((src[i+0] & 7) << 2) | (src[i+1] >> 6)];
			*dst++ = base32t[(src[i+1] >> 1) & 31];
			if (i + 2 < slen) {
				//printf("oi!2\n");
				*dst++ = base32t[((src[i+1] & 1) << 4) | (src[i+2] >> 4)];
				if (i + 3 < slen) {
					//printf("oi!3\n");
					*dst++ = base32t[((src[i+2] & 15) << 1) | (src[i+3] >> 7)];
					*dst++ = base32t[(src[i+3] >> 2) & 31];
					*dst++ = base32t[(src[i+3] & 3) << 3];
				}
				else {
					*dst++ = base32t[(src[i+2] & 15) << 1];
				}
			}
			else
				*dst++ = base32t[(src[i+1] & 1) << 4];
		}
		else
			*dst++ = base32t[(src[i+0] & 7) << 2];
	}
	//printhex(od, dst-od);
	*dst = 0;
	return dst;
}
