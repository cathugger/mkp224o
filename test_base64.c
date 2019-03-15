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
} tests0[] = {
	{ ""      ,""         },
	{ "f"     ,"Zg=="     },
	{ "fo"    ,"Zm8="     },
	{ "foo"   ,"Zm9v"     },
	{ "foob"  ,"Zm9vYg==" },
	{ "fooba" ,"Zm9vYmE=" },
	{ "foobar","Zm9vYmFy" },

	{ "foobarf"     ,"Zm9vYmFyZg=="     },
	{ "foobarfo"    ,"Zm9vYmFyZm8="     },
	{ "foobarfoo"   ,"Zm9vYmFyZm9v"     },
	{ "foobarfoob"  ,"Zm9vYmFyZm9vYg==" },
	{ "foobarfooba" ,"Zm9vYmFyZm9vYmE=" },
	{ "foobarfoobar","Zm9vYmFyZm9vYmFy" },
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
		if (strlen(buf) != BASE64_TO_LEN(strlen(tests0[i].in))) {
			printf("encoded length mismatch: got %d expected %d\n",
			       (int) strlen(buf), (int) BASE64_TO_LEN(strlen(tests0[i].in)));
			return 1;
		}
		if (!base64_valid(buf,0)) {
			printf("encoded data is considered invalid\n");
			return 1;
		}
		r = base64_from((u8 *)buf2, buf, strlen(buf));
		buf2[r] = '\000';
		if (strcmp(buf2, tests0[i].in) != 0) {
			printf("invalid decoding result: encoded \"%s\", decoded as \"%s\", but expected \"%s\".\n",
			       tests0[i].out, buf2, tests0[i].in);
			return 1;
		}
	}
	return 0;
}
