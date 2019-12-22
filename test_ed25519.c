#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include "types.h"
#include "base16.h"
#include "ed25519/ed25519.h"
#include "testutil.h"

struct pktest {
	const char *seed;
	const char *secret;
	const char *public;
} test0[] = {
	{
		"26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36",
		"c0a4de23cc64392d85aa1da82b3defddbea946d13bb053bf8489fa9296281f49"
		"5022f1f7ec0dcf52f07d4c7965c4eaed121d5d88d0a8ff546b06116a20e97755",
		"c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894",
	},
	{
		"fba7a5366b5cb98c2667a18783f5cf8f4f8d1a2ce939ad22a6e685edde85128d",
		"18a8a69a06790dac778e882f7e868baacfa12521a5c058f5194f3a729184514a"
		"2a656fe7799c3e41f43d756da8d9cd47a061316cfe6147e23ea2f90d1ca45f30",
		"1519a3b15816a1aafab0b213892026ebf5c0dc232c58b21088d88cb90e9b940d"
	},
};

#define SEEDBYTES 32
#define SECRETKEYBYTES 64
#define PUBLICKEYBYTES 32

int main(void)
{
	u8 seedbuf[SEEDBYTES];
	u8 secretbuf1[SECRETKEYBYTES];
	u8 secretbuf2[SECRETKEYBYTES];
	u8 publicbuf1[PUBLICKEYBYTES];
	u8 publicbuf2[PUBLICKEYBYTES];
	u8 mask;
	char str1[1024], str2[1024];
	for (size_t i = 0; i < sizeof(test0)/sizeof(test0[0]); ++i) {
		base16_from(seedbuf, &mask, test0[i].seed);
		base16_from(secretbuf1, &mask, test0[i].secret);
		base16_from(publicbuf1, &mask, test0[i].public);
		ed25519_seckey_expand(secretbuf2, seedbuf);
		WARNF(memcmp(secretbuf1, secretbuf2, SECRETKEYBYTES) == 0) {
			base16_to(str1, secretbuf1, sizeof(secretbuf1));
			base16_to(str2, secretbuf2, sizeof(secretbuf2));
			fprintf(stderr, "expected: %s got %s\n", str1, str2);
		}
		ed25519_pubkey(publicbuf2, secretbuf1);
		WARNF(memcmp(publicbuf1, publicbuf2, PUBLICKEYBYTES) == 0) {
			base16_to(str1, publicbuf1, sizeof(publicbuf1));
			base16_to(str2, publicbuf2, sizeof(publicbuf2));
			fprintf(stderr, "expected: %s got %s\n", str1, str2);
		}
	}

	return 0;
}
