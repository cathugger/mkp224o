#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sodium/randombytes.h>
#ifdef PASSPHRASE
#include <sodium/crypto_hash_sha256.h>
#endif
#include <sodium/utils.h>

#include "types.h"
#include "likely.h"
#include "vec.h"
#include "base32.h"
#include "keccak.h"
#include "ioutil.h"
#include "common.h"
#include "yaml.h"

#include "worker.h"

#include "filters.h"

#ifndef _WIN32
#define FSZ "%zu"
#else
#define FSZ "%Iu"
#endif

// additional 0 terminator is added by C
const char * const pkprefix = "== ed25519v1-public: type0 ==\0\0";
const char * const skprefix = "== ed25519v1-secret: type0 ==\0\0";

static const char checksumstr[] = ".onion checksum";
#define checksumstrlen (sizeof(checksumstr) - 1) // 15

pthread_mutex_t keysgenerated_mutex;
volatile size_t keysgenerated = 0;
volatile int endwork = 0;

int yamloutput = 0;
int yamlraw = 0;
int numwords = 1;
size_t numneedgenerate = 0;

// output directory
char *workdir = 0;
size_t workdirlen = 0;


#ifdef PASSPHRASE
// How many times we loop before a reseed
#define DETERMINISTIC_LOOP_COUNT (1<<24)

pthread_mutex_t determseed_mutex;
u8 determseed[SEED_LEN];
int pw_skipnear = 0;
int pw_warnnear = 0;
#endif


char *makesname(void)
{
	char *sname = (char *) malloc(workdirlen + ONION_LEN + 63 + 1);
	if (!sname)
		abort();
	if (workdir)
		memcpy(sname,workdir,workdirlen);
	return sname;
}

static void onionready(char *sname,const u8 *secret,const u8 *pubonion,int warnnear)
{
	if (endwork)
		return;

	if (numneedgenerate) {
		pthread_mutex_lock(&keysgenerated_mutex);
		if (keysgenerated >= numneedgenerate) {
			pthread_mutex_unlock(&keysgenerated_mutex);
			return;
		}
		++keysgenerated;
		if (keysgenerated == numneedgenerate)
			endwork = 1;
		pthread_mutex_unlock(&keysgenerated_mutex);
	}

	// disabled as this was never ever triggered as far as I'm aware
#if 0
	// Sanity check that the public key matches the private one.
	ge_p3 ALIGN(16) point;
	u8 testpk[PUBLIC_LEN];
	ge_scalarmult_base(&point,&secret[SKPREFIX_SIZE]);
	ge_p3_tobytes(testpk,&point);
	if (memcmp(testpk,&pubonion[PKPREFIX_SIZE],PUBLIC_LEN) != 0)
		abort();
#endif

	if (!yamloutput) {
		if (createdir(sname,1) != 0) {
			pthread_mutex_lock(&fout_mutex);
			fprintf(stderr,"ERROR: could not create directory \"%s\" for key output\n",sname);
			pthread_mutex_unlock(&fout_mutex);
			return;
		}

		strcpy(&sname[onionendpos],"/hs_ed25519_secret_key");
		writetofile(sname,secret,FORMATTED_SECRET_LEN,1);

		strcpy(&sname[onionendpos],"/hs_ed25519_public_key");
		writetofile(sname,pubonion,FORMATTED_PUBLIC_LEN,0);

		strcpy(&sname[onionendpos],"/hostname");
		FILE *hfile = fopen(sname,"w");
		sname[onionendpos] = '\n';
		if (hfile) {
			fwrite(&sname[direndpos],ONION_LEN + 1,1,hfile);
			fclose(hfile);
		}
		if (fout) {
			pthread_mutex_lock(&fout_mutex);
#ifdef PASSPHRASE
			const char * const pwarn = " warn:near\n";
			if (warnnear)
				strcpy(&sname[onionendpos],pwarn);
			const size_t oprintlen = printlen;
			const size_t printlen = oprintlen + (warnnear ? strlen(pwarn)-1 : 0);
#endif
			fwrite(&sname[printstartpos],printlen,1,fout);
			fflush(fout);
			pthread_mutex_unlock(&fout_mutex);
		}
	}
	else
		yamlout_writekeys(&sname[direndpos],pubonion,secret,yamlraw);
}

#include "filters_inc.inc.h"
#include "filters_worker.inc.h"

#ifdef STATISTICS
#define ADDNUMSUCCESS ++st->numsuccess.v
#else
#define ADDNUMSUCCESS do ; while (0)
#endif


union pubonionunion {
	u8 raw[PKPREFIX_SIZE + PUBLIC_LEN + 32];
	struct {
		u64 prefix[4];
		u64 key[4];
		u64 hash[4];
	} i;
} ;

/*
// little endian inc
static void addsk32(u8 *sk)
{
	register unsigned int c = 8;
	for (size_t i = 0;i < 32;++i) {
		c = (unsigned int)sk[i] + c; sk[i] = c & 0xFF; c >>= 8;
		// unsure if needed
		if (!c) break;
	}
}
*/

// 0123 4567 xxxx --3--> 3456 7xxx
// 0123 4567 xxxx --1--> 1234 567x
static inline void shiftpk(u8 *dst,const u8 *src,size_t sbits)
{
	size_t i,sbytes = sbits / 8;
	sbits %= 8;
	for (i = 0;i + sbytes < PUBLIC_LEN;++i) {
		dst[i] = (u8) ((src[i+sbytes] << sbits) |
			(src[i+sbytes+1] >> (8 - sbits)));
	}
	for(;i < PUBLIC_LEN;++i)
		dst[i] = 0;
}



// in little-endian order, 32 bytes aka 256 bits
static void addsztoscalar32(u8 *dst,size_t v)
{
	int i;
	u32 c = 0;
	for (i = 0;i < 32;++i) {
		c += *dst + (v & 0xFF); *dst = c & 0xFF; c >>= 8;
		v >>= 8;
		++dst;
	}
}



#ifdef PASSPHRASE
static void reseedright(u8 sk[SECRET_LEN])
{
	crypto_hash_sha256_state state;
	crypto_hash_sha256_init(&state);
	// old right side
	crypto_hash_sha256_update(&state,&sk[32],32);
	// new random data
	randombytes(&sk[32],32);
	crypto_hash_sha256_update(&state,&sk[32],32);
	// put result in right side
	crypto_hash_sha256_final(&state,&sk[32]);
}
#endif // PASSPHRASE



#if !defined(BATCHNUM)
	#define BATCHNUM 2048
#endif


#include "ed25519/ed25519.h"

#include "worker_impl.inc.h"

size_t worker_batch_memuse(void)
{
	size_t s = 0,x;

#ifdef ED25519_ref10
	x = crypto_sign_ed25519_ref10_worker_batch_memuse();
	if (x > s)
		s = x;
#endif

#ifdef ED25519_amd64_51_30k
	x = crypto_sign_ed25519_amd64_51_30k_worker_batch_memuse();
	if (x > s)
		s = x;
#endif

#ifdef ED25519_amd64_64_24k
	x = crypto_sign_ed25519_amd64_64_24k_worker_batch_memuse();
	if (x > s)
		s = x;
#endif

#ifdef ED25519_donna
	x = crypto_sign_ed25519_donna_worker_batch_memuse();
	if (x > s)
		s = x;
#endif

	return s;
}

void worker_init(void)
{
#ifdef ED25519_ref10
	crypto_sign_ed25519_ref10_ge_initeightpoint();
#endif

#ifdef ED25519_amd64_51_30k
	crypto_sign_ed25519_amd64_51_30k_ge_initeightpoint();
#endif

#ifdef ED25519_amd64_64_24k
	crypto_sign_ed25519_amd64_64_24k_ge_initeightpoint();
#endif

#ifdef ED25519_donna
	crypto_sign_ed25519_donna_ge_initeightpoint();
#endif
}
