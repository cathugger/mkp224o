#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "base64.h"
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
	{"f", "Zg==", "f"},
	{"fo", "Zm8=", "fo"},
	{"foo", "Zm9v", "foo"},
	{"foob", "Zm9vYg==", "foob"},
	{"fooba", "Zm9vYmE=", "fooba"},
	{"foobar", "Zm9vYmFy", "foobar"},
};

int main(void)
{
	char buf[1024], buf2[1024];
	size_t r;
	for (size_t i = 0; i < sizeof(tests0)/sizeof(tests0[0]); ++i) {
		base64_to(buf, (const u8 *)tests0[i].in, strlen(tests0[i].in));
		if (strcmp(buf, tests0[i].out) != 0) {
			printf("invalid encoding result: \"%s\" -> encoded as \"%s\", but expected \"%s\".\n",
						 tests0[i].in, buf, tests0[i].out);
			return 1;
		}
		if (!base64_valid(buf,0)) {
			printf("encoded data is considered invalid\n");
			return 3;
		}
		r = base64_from((u8 *)buf2, buf, strlen(buf));
		buf2[r] = '\0';
		if (strcmp(buf2, tests0[i].rev) != 0) {
			printf("invalid decoding result: encoded \"%s\", decoded as \"%s\", but expected \"%s\".\n",
						 tests0[i].out, buf2, tests0[i].rev);
			return 2;
		}
	}
	return 0;
}
