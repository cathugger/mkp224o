#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "base64.h"

static const char base64t[64] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/',
};

char *base64_to(char *dst,const u8 *src,size_t slen)
{
	if (!slen) {
		*dst = '\0';
		return dst;
	}

	for(size_t i = 0; i < slen;) {
		u32 threebytes = 0;
		threebytes |= (i < slen ? (unsigned char)src[i++] : (unsigned char)0) << (2 * 8);
		threebytes |= (i < slen ? (unsigned char)src[i++] : (unsigned char)0) << (1 * 8);
		threebytes |= (i < slen ? (unsigned char)src[i++] : (unsigned char)0) << (0 * 8);

		*dst++ = base64t[(threebytes >> (3 * 6)) & 63];
		*dst++ = base64t[(threebytes >> (2 * 6)) & 63];
		*dst++ = base64t[(threebytes >> (1 * 6)) & 63];
		*dst++ = base64t[(threebytes >> (0 * 6)) & 63];
	}

	switch (slen % 3) {
		case 0 : break;
		case 1 : {
			*(dst-2) = '=';
			*(dst-1) = '=';
			break;
		}
		case 2 : {
			*(dst-1) = '=';
			break;
		}
	}

	*dst = '\0';
	return dst;
}
