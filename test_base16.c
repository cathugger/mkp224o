#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "base16.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>

/*
   BASE16("") = ""
   BASE16("f") = "66"
   BASE16("fo") = "666F"
   BASE16("foo") = "666F6F"
   BASE16("foob") = "666F6F62"
   BASE16("fooba") = "666F6F6261"
   BASE16("foobar") = "666F6F626172"
*/

struct texttestcase {
	const char *in;
	const char *out;
	const char *rev;
} tests0[] = {
	{"", "", ""},
	{"f", "66", "f"},
	{"fo", "666F", "fo"},
	{"foo", "666F6F", "foo"},
	{"foob", "666F6F62", "foob"},
	{"fooba", "666F6F6261", "fooba"},
	{"foobar", "666F6F626172", "foobar"},
};

int main(void)
{
	char buf[1024], buf2[1024], mask;
	size_t r;
	for (size_t i = 0; i < sizeof(tests0)/sizeof(tests0[0]); ++i) {
		base16_to(buf, (const u8 *)tests0[i].in, strlen(tests0[i].in));
		assert(strcmp(buf, tests0[i].out) == 0);
		r = base16_from((u8 *)buf2, (u8 *)&mask, buf);
		buf2[r] = 0;
		//fprintf(stderr, "r:%d, mask:%02X\n", (int)r, ((unsigned int)mask) & 0xFF);
		//assert(r == strlen(buf2));
		//assert(r == strlen(tests0[i].rev));
		//fprintf(stderr, "%s -- %s\n", buf2, tests0[i].rev);
		assert(strcmp(buf2, tests0[i].rev) == 0);
	}
	
	return 0;
}
