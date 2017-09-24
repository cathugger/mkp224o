#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sodium/randombytes.h>
#include "ed25519/ref10/ed25519_ref10.h"
#include "ed25519/ref10/ge.h"

#include <sys/stat.h>

#include "types.h"
#include "vec.h"
#include "base32.h"
#include "keccak.h"

// additional leading zero is added by C
static const char * const pkprefix = "== ed25519v1-public: type0 ==\0\0";
#define pkprefixlen (29 + 3)
static const char * const skprefix = "== ed25519v1-secret: type0 ==\0\0";
#define skprefixlen (29 + 3)
static const char * const checksumstr = ".onion checksum";
#define checksumstrlen 15

// output directory
static char *workdir = 0;
static size_t workdirlen = 0;

static int quietflag = 0;

#define SECRET_LEN 64
#define PUBLIC_LEN 32
#define SEED_LEN   32
// with checksum + version num
#define PUBONION_LEN (PUBLIC_LEN + 3)
// with newline included
#define ONIONLEN 62

static size_t onionendpos;   // end of .onion within string
static size_t direndpos;     // end of dir before .onion within string
static size_t printstartpos; // where to start printing from
static size_t printlen;      // precalculated, related to printstartpos

static FILE *fout;
static pthread_mutex_t fout_mutex;

static volatile int endwork = 0;
static volatile size_t keysgenerated = 0;

struct strfilter {
	char *str;
	size_t len;
} ;

VEC_STRUCT(filtervec, struct strfilter) filters;

static void filters_init()
{
	VEC_INIT(filters);
}

static void filters_add(const char *filter)
{
	struct strfilter sf;
	sf.len = strlen(filter);
	sf.str = malloc(sf.len + 1);
	memcpy(sf.str, filter, sf.len + 1);
	VEC_ADD(filters, sf)
}

static void filters_clean()
{
	for (size_t i = 0; i < VEC_LENGTH(filters); ++i) {
		free(VEC_BUF(filters, i).str);
	}
	VEC_FREE(filters);
}

static void loadfilterfile(const char *fname)
{
	char buf[128];
	FILE *f = fopen(fname, "r");
	while(fgets(buf, sizeof(buf), f)) {
		char *p = buf;
		while(*p++)
			if(*p == '\n')
				*p = 0;
		if (*buf && *buf != '#' && memcmp(buf, "//", 2) != 0)
			filters_add(buf);
	}
}

static void printfilters()
{
	fprintf(stderr, "current filters:\n");
	for (size_t i = 0; i < VEC_LENGTH(filters); ++i) {
		fprintf(stderr, "\t%s\n", VEC_BUF(filters, i).str);
	}
}


static void onionready(char *sname, const u8 *secret, const u8 *pubonion)
{
	FILE *fh;

	if (mkdir(sname, 0700) != 0)
		return;
	
	strcpy(&sname[onionendpos], "/hostname");
	fh = fopen(sname, "w");
	if (fh) {
		sname[onionendpos] = '\n';
		fwrite(&sname[direndpos], ONIONLEN+1, 1, fh);
		fclose(fh);
	}

	strcpy(&sname[onionendpos], "/hs_ed25519_public_key");
	fh = fopen(sname, "wb");
	if (fh) {
		fwrite(pubonion, pkprefixlen + PUBLIC_LEN, 1, fh);
		fclose(fh);
	}

	strcpy(&sname[onionendpos], "/hs_ed25519_secret_key");
	fh = fopen(sname, "wb");
	if (fh) {
		fwrite(secret, skprefixlen + SECRET_LEN, 1, fh);
		fclose(fh);
	}

	sname[onionendpos] = '\n';
	pthread_mutex_lock(&fout_mutex);
	if (fout) {
		fwrite(&sname[printstartpos], printlen, 1, fout);
		fflush(fout);
	}
	++keysgenerated;
	pthread_mutex_unlock(&fout_mutex);
}

// little endian inc
static void addseed(u8 *seed)
{
	register unsigned int c = 1;
	for (size_t i = 0; i < SEED_LEN; ++i) {
		c = (unsigned int)seed[i] + c; seed[i] = c & 0xFF; c >>= 8;
		// unsure if needed
		if (!c) break;
	}
}

static void *dowork(void *task)
{
	u8 pubonion[pkprefixlen + PUBONION_LEN];
	u8 secret[skprefixlen + SECRET_LEN];
	u8 seed[SEED_LEN];
	u8 hashsrc[checksumstrlen + PUBLIC_LEN + 1];
	size_t i;
	char *sname;

	memcpy(secret, skprefix, skprefixlen);
	memcpy(pubonion, pkprefix, pkprefixlen);
	pubonion[pkprefixlen + PUBLIC_LEN + 2] = 0x03; // version
	memcpy(hashsrc, checksumstr, checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = alloca(workdirlen + ONIONLEN + 63 + 1);
	if (workdir)
		memcpy(sname, workdir, workdirlen);

initseed:
	randombytes(seed, sizeof(seed));

again:
	if (endwork)
		goto end;

	// TODO technically we could manipulate secret/public keys directly
	ed25519_ref10_seckey_expand(&secret[skprefixlen], seed);
	ed25519_ref10_pubkey(&pubonion[pkprefixlen], &secret[skprefixlen]);
	// we could actually avoid this by using more specialised filters
	base32_to(&sname[direndpos], &pubonion[pkprefixlen], PUBLIC_LEN);
	for (i = 0;i < VEC_LENGTH(filters);++i) {
		if (strncmp(&sname[direndpos], VEC_BUF(filters, i).str, VEC_BUF(filters, i).len) == 0) {
			memcpy(&hashsrc[checksumstrlen], &pubonion[pkprefixlen], PUBLIC_LEN);
			FIPS202_SHA3_256(hashsrc, sizeof(hashsrc), &pubonion[pkprefixlen + PUBLIC_LEN]);
			strcpy(base32_to(&sname[direndpos], &pubonion[pkprefixlen], PUBONION_LEN), ".onion");
			onionready(sname, secret, pubonion);
			goto initseed;
		}
	}
	addseed(seed);
	goto again;

end:
	return 0;
}

/* The basepoint multiplied by 8. */
static const ge_cached ge_eightpoint = {
  /* YplusX */
  {
    48496028, -16430416, 15164263, 11885335, 60784617, -4866353, 46481863,
    -2771805, 9708580, 2387263
  },
  /* YmunusX */
  {
    -10173472, -5540046, 21277639, 4080693, 1932823, -14916249, -9515873,
    -21787995, -36575460, 29827857
  },
  /* Z */
  {
    25143927, -10256223, -3515585, 5715072, 19432778, -14905909, 22462083,
    -8862871, 13226552, 743677
  },
  /* T2d */
  {
    -784818, -8208065, -28479270, 5551579, 15746872, 4911053, 19117091,
    11267669, -24569594, 14624995
  }
};

static void addu64toscalar32(u8 *dst, u64 v)
{
	int i;
	u32 c = 0;
	for (i = 0;i < 8;++i) {
		c += *dst + (v & 0xFF);
		*dst = c & 0xFF;
		c >>= 8;
		v >>= 8;
		dst++;
	}
}

static void *dofastwork(void *task)
{
	u8 pubonion[pkprefixlen + PUBONION_LEN];
	u8 secret[skprefixlen + SECRET_LEN];
	u8 * const sk = &secret[skprefixlen];
	u8 seed[SEED_LEN];
	u8 hashsrc[checksumstrlen + PUBLIC_LEN + 1];
	ge_p3 ge_public;
	u64 counter;
	size_t i;
	char *sname;

	memcpy(secret, skprefix, skprefixlen);
	memcpy(pubonion, pkprefix, pkprefixlen);
	pubonion[pkprefixlen + PUBLIC_LEN + 2] = 0x03; // version
	memcpy(hashsrc, checksumstr, checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = alloca(workdirlen + ONIONLEN + 63 + 1);
	if (workdir)
		memcpy(sname, workdir, workdirlen);

initseed:
	randombytes(seed, sizeof(seed));
	ed25519_ref10_seckey_expand(&secret[skprefixlen], seed);
	
	ge_scalarmult_base(&ge_public,sk);
	ge_p3_tobytes(&pubonion[pkprefixlen],&ge_public);
	
	for (counter = 0;counter < U64_MAX-8;counter += 8) {
		ge_p1p1 sum;
		
		if (endwork)
			goto end;
		
		// we could actually avoid this by using more specialised filters
		base32_to(&sname[direndpos], &pubonion[pkprefixlen], PUBLIC_LEN);
		for (i = 0;i < VEC_LENGTH(filters);++i) {
			if (strncmp(&sname[direndpos], VEC_BUF(filters, i).str, VEC_BUF(filters, i).len) == 0) {
				// found!
				// update secret key with counter
				addu64toscalar32(sk, counter);
				// sanity check
				if (((sk[0] & 248) == sk[0]) && (((sk[31] & 63) | 64) == sk[31])) {
					/* These operations should be a no-op. */
					sk[0] &= 248;
					sk[31] &= 63;
					sk[31] |= 64;
				}
				else goto initseed;
				
				// calc checksum
				memcpy(&hashsrc[checksumstrlen], &pubonion[pkprefixlen], PUBLIC_LEN);
				FIPS202_SHA3_256(hashsrc, sizeof(hashsrc), &pubonion[pkprefixlen + PUBLIC_LEN]);
				// full name
				strcpy(base32_to(&sname[direndpos], &pubonion[pkprefixlen], PUBONION_LEN), ".onion");
				onionready(sname, secret, pubonion);
				// don't reuse same seed
				goto initseed;
			}
		}

		// next
		ge_add(&sum, &ge_public, &ge_eightpoint);
		ge_p1p1_to_p3(&ge_public, &sum);
		ge_p3_tobytes(&pubonion[pkprefixlen],&ge_public);
	}
	goto initseed;

end:
	return 0;
}

void printhelp(const char *progname)
{
	fprintf(stderr,
		"Usage: %s filter [filter...] [options]\n"
		"       %s -f filterfile [options]\n"
		"Options:\n"
		"\t-h  - print help\n"
		"\t-f  - instead of specifying filter(s) via commandline, specify filter file which contains filters separated by newlines\n"
		"\t-q  - do not print diagnostic output to stderr\n"
		"\t-x  - do not print onion names\n"
		"\t-o filename  - output onion names to specified file\n"
		"\t-F  - include directory names in onion names output\n"
		"\t-d dirname  - output directory\n"
		"\t-t numthreads  - specify number of threads (default - auto)\n"
		"\t-n numkeys  - specify number of keys (default - 0 - unlimited)\n"
		"\t-z  - use faster, experimental key generation method\n"
		,progname,progname);
	exit(1);
}

void setworkdir(const char *wd)
{
	free(workdir);
	size_t l = strlen(wd);
	if (!l) {
		workdir = 0;
		workdirlen = 0;
		if (!quietflag)
			fprintf(stderr, "unset workdir\n");
		return;
	}
	int needslash = 0;
	if (wd[l-1] != '/')
		needslash = 1;
	char *s = malloc(l + needslash + 1);
	memcpy(s, wd, l);
	if (needslash)
		s[l++] = '/';
	s[l] = 0;
	
	workdir = s;
	workdirlen = l;
	if (!quietflag)
		fprintf(stderr, "set workdir: %s\n", workdir);
}

VEC_STRUCT(threadvec, pthread_t);

int main(int argc, char **argv)
{
	char *outfile = 0;
	const char *arg;
	int ignoreargs = 0;
	int dirnameflag = 0;
	int numthreads = 0;
	int fastkeygen = 0;
	struct threadvec threads;
	int tret;
	
	filters_init();
	
	fout = stdout;
	pthread_mutex_init(&fout_mutex, 0);

	const char *progname = argv[0];
	if (argc <= 1)
		printhelp(progname);
	argc--, argv++;

	while (argc--) {
		arg = *argv++;
		if (!ignoreargs && *arg == '-') {
			int numargit = 0;
		nextarg:
			++arg;
			++numargit;
			if (*arg == '-') {
				if (numargit > 1) {
					fprintf(stderr, "unrecognised argument: -\n");
					exit(1);
				}
				++arg;
				if (!*arg)
					ignoreargs = 1;
				else if (!strcmp(arg, "help"))
					printhelp(progname);
				else {
					fprintf(stderr, "unrecognised argument: --%s\n", arg);
					exit(1);
				}
				numargit = 0;
			}
			else if (*arg == 0) {
				if (numargit == 1)
					ignoreargs = 1;
				continue;
			}
			else if (*arg == 'h')
				printhelp(progname);
			else if (*arg == 'f') {
				if (argc--)
					loadfilterfile(*argv++);
				else {
					fprintf(stderr, "additional argument required\n");
					exit(1);
				}
			}
			else if (*arg == 'q')
				++quietflag;
			else if (*arg == 'x')
				fout = 0;
			else if (*arg == 'o') {
				if (argc--)
					outfile = *argv++;
				else {
					fprintf(stderr, "additional argument required\n");
					exit(1);
				}
			}
			else if (*arg == 'F')
				dirnameflag = 1;
			else if (*arg == 'd') {
				if (argc--) {
					setworkdir(*argv++);
				}
				else {
					fprintf(stderr, "additional argument required\n");
				}
			}
			else if (*arg == 't') {
				if (argc--)
					numthreads = atoi(*argv++);
				else {
					fprintf(stderr, "additional argument required\n");
					exit(1);
				}
			}
			else if (*arg == 'z')
				fastkeygen = 1;
			else {
				fprintf(stderr, "unrecognised argument: -%c\n", *arg);
				exit(1);
			}
			if (numargit)
				goto nextarg;
		}
		else filters_add(arg);
	}
	
	if (outfile)
		fout = fopen(outfile, "w");

	if (!quietflag)
		printfilters();

	if (workdir)
		mkdir(workdir, 0700);
	
	direndpos = workdirlen;
	onionendpos = workdirlen + ONIONLEN;
	
	if (!dirnameflag) {
		printstartpos = direndpos;
		printlen = ONIONLEN + 1;
	} else {
		printstartpos = 0;
		printlen = onionendpos + 1;
	}
	
	if (numthreads <= 0) {
		// TODO: autodetect
		numthreads = 1;
	}
	
	VEC_INIT(threads);
	VEC_ADDN(threads, pthread_t, numthreads);
	
	for (size_t i = 0; i < VEC_LENGTH(threads); ++i) {
		tret = pthread_create(&VEC_BUF(threads, i), 0, fastkeygen ? dofastwork : dowork, 0);
		if (tret) {
			fprintf(stderr, "error while making %dth thread: %d\n", (int)i, tret);
			exit(1);
		}
	}
	fprintf(stderr, "waiting for threads to finish...\n");
	for (size_t i = 0; i < VEC_LENGTH(threads); ++i) {
		pthread_join(VEC_BUF(threads, i), 0);
	}
	fprintf(stderr, "done, quitting\n");

	pthread_mutex_destroy(&fout_mutex);
	filters_clean();
	
	return 0;
}
