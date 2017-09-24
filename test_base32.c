#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "base32.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <sodium/randombytes.h>

struct texttestcase {
	const char *in;
	const char *out;
	const char *rev;
} tests0[] = {
	{"", "", ""},
	{"f", "my", "f"},
	{"fo", "mzxq", "fo"},
	{"foo", "mzxw6", "foo"},
	{"foob", "mzxw6yq", "foob"},
	{"fooba", "mzxw6ytb", "fooba"},
	{"foobar", "mzxw6ytboi", "foobar"},
};

/*
r:0, mask:FF
 -- 
r:2, mask:C0
f -- f
r:3, mask:F0
fo -- fo
r:4, mask:80
foo -- foo
r:5, mask:E0
foob -- foob
r:5, mask:FF
fooba -- fooba
r:7, mask:C0
foobar -- foobar
*/

/*
struct masktestcase {
	const char *src;
	u8 mask;
} tests1[] = {
	{"", 0x00},
	{"a", 0x00},
	{"ab", 0x00},
	{"abc", 0x00},
	{"abcd", 0x00},
	{"abcde", 0x00},
	{"abcdef", 0x00},
	{"abcdefg", 0x00},
	{"abcdefgh", 0x00},
	{"abcdefghi", 0x00},
	{"abcdefghij", 0x00},
};
*/

int main()
{
	char buf[1024], buf2[1024], mask;
	size_t r;
	for (size_t i = 0; i < sizeof(tests0)/sizeof(tests0[0]); ++i) {
		base32_to(buf, (const u8 *)tests0[i].in, strlen(tests0[i].in));
		assert(strcmp(buf, tests0[i].out) == 0);
		r = base32_from((u8 *)buf2, (u8 *)&mask, buf);
		buf2[r] = 0;
		if (r > 0) {
			assert((buf2[r-1] & ~mask) == 0);
		}
		//fprintf(stderr, "r:%d, mask:%02X\n", (int)r, ((unsigned int)mask) & 0xFF);
		//assert(r == strlen(buf2));
		//assert(r == strlen(tests0[i].rev));
		//fprintf(stderr, "%s -- %s\n", buf2, tests0[i].rev);
		assert(strcmp(buf2, tests0[i].rev) == 0);
	}
	
	//randombytes_buf(buf, 128);
	//base32_to(buf2, (const u8 *)buf, 128);
	//fprintf(stderr, ">%s\n", buf2);
	
	return 0;
}