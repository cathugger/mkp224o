#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sodium/core.h>
#include <sodium/randombytes.h>
#ifdef PASSPHRASE
#include <sodium/crypto_pwhash.h>
#endif
#include <sodium/utils.h>

#include "types.h"
#include "vec.h"
#include "base32.h"
#include "cpucount.h"
#include "keccak.h"
#include "ioutil.h"
#include "common.h"
#include "yaml.h"
#include "headers.h"

#include "filters.h"

#include "worker.h"

#include "likely.h"

#ifndef _WIN32
#define FSZ "%zu"
#else
#define FSZ "%Iu"
#endif

// Argon2 hashed passphrase stretching settings
// NOTE: changing these will break compatibility
#define PWHASH_OPSLIMIT 48
#define PWHASH_MEMLIMIT 64 * 1024 * 1024
#define PWHASH_ALG      crypto_pwhash_ALG_ARGON2ID13

static int quietflag = 0;
static int verboseflag = 0;
#ifndef PCRE2FILTER
static int wantdedup = 0;
#endif

// 0, direndpos, onionendpos
// printstartpos = either 0 or direndpos
// printlen      = either onionendpos + 1 or ONION_LEN + 1 (additional 1 is for newline)
size_t onionendpos;   // end of .onion within string
size_t direndpos;     // end of dir before .onion within string
size_t printstartpos; // where to start printing from
size_t printlen;      // precalculated, related to printstartpos

pthread_mutex_t fout_mutex;
FILE *fout;

#ifdef PASSPHRASE
u8 orig_determseed[SEED_LEN];
const char *checkpointfile = 0;
#endif

static void termhandler(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		endwork = 1;
		break;
	}
}

#ifdef STATISTICS
struct tstatstruct {
	u64 numcalc;
	u64 numsuccess;
	u64 numrestart;
	u32 oldnumcalc;
	u32 oldnumsuccess;
	u32 oldnumrestart;
} ;
VEC_STRUCT(tstatsvec,struct tstatstruct);
#endif

static void printhelp(FILE *out,const char *progname)
{
	//   0         1         2         3         4         5         6         7
	//   01234567890123456789012345678901234567890123456789012345678901234567890123456789
	fprintf(out,
		"Usage: %s FILTER [FILTER...] [OPTION]\n"
		"       %s -f FILTERFILE [OPTION]\n"
		"Options:\n"
		"  -f FILTERFILE         specify filter file which contains filters separated\n"
		"                        by newlines\n"
		"  -D                    deduplicate filters\n"
		"  -q                    do not print diagnostic output to stderr\n"
		"  -x                    do not print onion names\n"
		"  -v                    print more diagnostic data\n"
		"  -o FILENAME           output onion names to specified file (append)\n"
		"  -O FILENAME           output onion names to specified file (overwrite)\n"
		"  -F                    include directory names in onion names output\n"
		"  -d DIRNAME            output directory\n"
		"  -t NUMTHREADS         specify number of threads to utilise\n"
		"                        (default - try detecting CPU core count)\n"
		"  -j NUMTHREADS         same as -t\n"
		"  -n NUMKEYS            specify number of keys (default - 0 - unlimited)\n"
		"  -N NUMWORDS           specify number of words per key (default - 1)\n"
		"  -Z                    use \"slower\" key generation method (initial default)\n"
		"  -z                    use \"faster\" key generation method (later default)\n"
		"  -B                    use batching key generation method\n"
		"                        (>10x faster than -z, current default)\n"
		"  -s                    print statistics each 10 seconds\n"
		"  -S SECONDS            print statistics every specified amount of seconds\n"
		"  -T                    do not reset statistics counters when printing\n"
		"  -y                    output generated keys in YAML format instead of\n"
		"                        dumping them to filesystem\n"
		"  -Y [FILENAME [host.onion]]\n"
		"                        parse YAML encoded input and extract key(s) to\n"
		"                        filesystem\n"
#ifdef PASSPHRASE
		"  -p PASSPHRASE         use passphrase to initialize the random seed with\n"
		"  -P                    same as -p, but takes passphrase from PASSPHRASE\n"
		"                        environment variable\n"
		"  --checkpoint filename\n"
		"                        load/save checkpoint of progress to specified file\n"
		"                        (requires passphrase)\n"
#endif
		"      --rawyaml         raw (unprefixed) public/secret keys for -y/-Y\n"
		"                        (may be useful for tor controller API)\n"
		"  --basekey base.pub\n"
		"                        trustless mining: the private keys found will need\n"
		"                        to be --combine'd with the private parts of all\n"
		"                        basekeys used\n"
		"  --genbase base.priv base.pub\n"
		"                        generate base keys for trustless mining\n"
		"  --combine halfkey base.priv..\n"
		"                        combine a mined hs_secret key with base key(s)\n"
		"  -h, --help, --usage   print help to stdout and quit\n"
		"  -V, --version         print version information to stdout and exit\n"
		,progname,progname);
	fflush(out);
}

static void printversion(void)
{
	fprintf(stdout,"mkp224o " VERSION "\n");
	fflush(stdout);
}

static void e_additional(void)
{
	fprintf(stderr,"additional argument required\n");
	exit(1);
}

#ifndef STATISTICS
static void e_nostatistics(void)
{
	fprintf(stderr,"statistics support not compiled in\n");
	exit(1);
}
#endif

static void setworkdir(const char *wd)
{
	free(workdir);
	size_t l = strlen(wd);
	if (!l) {
		workdir = 0;
		workdirlen = 0;
		if (!quietflag)
			fprintf(stderr,"unset workdir\n");
		return;
	}
	unsigned needslash = 0;
	if (wd[l-1] != '/')
		needslash = 1;
	char *s = (char *) malloc(l + needslash + 1);
	if (!s)
		abort();
	memcpy(s,wd,l);
	if (needslash)
		s[l++] = '/';
	s[l] = 0;

	workdir = s;
	workdirlen = l;
	if (!quietflag)
		fprintf(stderr,"set workdir: %s\n",workdir);
}

#ifdef PASSPHRASE
static void setpassphrase(const char *pass)
{
	static u8 salt[crypto_pwhash_SALTBYTES] = {0};
	fprintf(stderr,"expanding passphrase (may take a while)...");
	if (crypto_pwhash(determseed,sizeof(determseed),
		pass,strlen(pass),salt,
		PWHASH_OPSLIMIT,PWHASH_MEMLIMIT,PWHASH_ALG) != 0)
	{
		fprintf(stderr," out of memory!\n");
		exit(1);
	}
	fprintf(stderr," done.\n");
}

static void savecheckpoint(void)
{
	u8 checkpoint[SEED_LEN];
	bool carry = 0;
	pthread_mutex_lock(&determseed_mutex);
	for (int i = 0; i < SEED_LEN; i++) {
		checkpoint[i] = determseed[i] - orig_determseed[i] - carry;
		carry = checkpoint[i] > determseed[i];
	}
	pthread_mutex_unlock(&determseed_mutex);

	if (syncwrite(checkpointfile,1,checkpoint,SEED_LEN) < 0) {
		pthread_mutex_lock(&fout_mutex);
		fprintf(stderr,"ERROR: could not save checkpoint to \"%s\"\n",checkpointfile);
		pthread_mutex_unlock(&fout_mutex);
	}
}

static volatile int checkpointer_endwork = 0;

static void *checkpointworker(void *arg)
{
	(void) arg;

	struct timespec ts;
	memset(&ts,0,sizeof(ts));
	ts.tv_nsec = 100000000;

	struct timespec nowtime;
	u64 ilasttime,inowtime;
	clock_gettime(CLOCK_MONOTONIC,&nowtime);
	ilasttime = (1000000 * (u64)nowtime.tv_sec) + ((u64)nowtime.tv_nsec / 1000);

	while (!unlikely(checkpointer_endwork)) {

		clock_gettime(CLOCK_MONOTONIC,&nowtime);
		inowtime = (1000000 * (u64)nowtime.tv_sec) + ((u64)nowtime.tv_nsec / 1000);

		if ((i64)(inowtime - ilasttime) >= 300 * 1000000 /* 5 minutes */) {
			savecheckpoint();
			ilasttime = inowtime;
		}
	}

	savecheckpoint();

	return 0;
}
#endif

VEC_STRUCT(threadvec,pthread_t);

#include "filters_inc.inc.h"
#include "filters_main.inc.h"

enum worker_type {
	WT_SLOW,
	WT_FAST,
	WT_BATCH,
};

// i'm so sorry for including an implementation header
// i didn't find another way to get access to the functions
#include "ed25519/ed25519_impl_pre.h"
static void genbase(const char *privpath, const char *pubpath)
{
	u8 base_sk[32];
	u8 base_pk[32];
	u8 base_extsk[64];
	ge_p3 ALIGN(16) A;
	FILE *fp;

	randombytes(base_sk, sizeof base_sk);
	ed25519_seckey_expand(base_extsk, base_sk);
	ge_scalarmult_base(&A, base_extsk);
	ge25519_pack(base_pk, &A);

	printf("writing private base key to '%s'\n", privpath);
	fp = fopen(privpath, "w");
	if (!fp) {
		perror("couldn't open");
		exit(1);
	}
	if (fwrite(HEADER_BASESK, 1, HEADER_BASESKLEN, fp) != HEADER_BASESKLEN) {
		perror("write");
		exit(1);
	}
	if (fwrite(base_sk, 1, 32, fp) != 32) {
		perror("write");
		exit(1);
	}
	fclose(fp);

	printf("writing public base key to '%s'\n", pubpath);
	fp = fopen(pubpath, "w");
	if (!fp) {
		perror("couldn't open");
		exit(1);
	}
	if (fwrite(HEADER_BASEPK, 1, HEADER_BASEPKLEN, fp) != HEADER_BASEPKLEN) {
		perror("write");
		exit(1);
	}
	if (fwrite(base_pk, 1, 32, fp) != 32) {
		perror("write");
		exit(1);
	}
	fclose(fp);

	puts("done.");
}

static void combine(int argc, char **argv)
{
	u8 halfkey[HEADER_HALFKEYLEN + SECRET_LEN + PUBLIC_LEN];
	u8 result[FORMATTED_SECRET_LEN];
	FILE *fp;
	const char *minedpath = argv[0];

	if (argc < 2) {
		fprintf(stderr, "--combine requires one or more base private keys after the mined key.\n");
		exit(1);
	}
 
	fp = fopen(minedpath, "r");
	if (fp == NULL) {
		perror("failed to open halfkey");
		exit(1);
	}
	if (fread(halfkey, sizeof halfkey, 1, fp) != 1) {
		perror("failed to read hs_secret_key");
		exit(1);
	}
	if (memcmp(halfkey, HEADER_HALFKEY, HEADER_HALFKEYLEN) != 0) {
		fprintf(stderr, "Invalid halfkey format. The halfkey must be the first argument.\n");
		exit(1);
	}
	fclose(fp);

	sc25519 ALIGN(16) a;
	sc25519_from32bytes(&a, &halfkey[HEADER_HALFKEYLEN]);

	for (int i = 1; i < argc; i++) {
		u8 base_sk[32], base_extsk[64];
		fp = fopen(argv[i], "r");
		if (fp == NULL) {
			perror("couldn't open basekey");
			exit(1);
		}
		if (fread(base_sk, 1, HEADER_BASESKLEN, fp) != HEADER_BASESKLEN) {
			perror("read");
			exit(1);
		}
		if (memcmp(base_sk, HEADER_BASESK, HEADER_BASESKLEN) != 0) {
			fprintf(stderr, "\"%s\" isn't a valid base secret key.\n", argv[i]);
			exit(1);
		}
		if (fread(base_sk, 1, sizeof base_sk, fp) != sizeof base_sk) {
			perror("read");
			exit(1);
		}
		fclose(fp);

		sc25519 ALIGN(16) b;
		ed25519_seckey_expand(base_extsk, base_sk);
		sc25519_from32bytes(&b, base_extsk);
		sc25519_add(&a, &a, &b);
	}

	ge_p3 ALIGN(16) A;
	ge25519_scalarmult_base(&A, &a);
	u8 pk[32];
	ge25519_pack(pk, &A);

	// Save secret scalar.
	memcpy(result, "== ed25519v1-secret: type0 ==\0\0\0", SKPREFIX_SIZE);
	sc25519_to32bytes(&result[SKPREFIX_SIZE], &a);

	// Compute the key's hash prefix.
	// See "Pseudorandom generation of r.", page 8 of https://ed25519.cr.yp.to/ed25519-20110926.pdf
	// Usually it's generated together with the secret scalar using a hash
	// function, but we can't do that here. As far as I can tell, it just
	// needs to be another secret value.
	// I'm setting it to a hash of the secret scalar to prevent generating
	// multiple keys with the same secret scalar but different hash prefixes,
	// which never occurs in normal ed25519.
	FIPS202_SHAKE256(&result[SKPREFIX_SIZE], 32, &result[64], 32);
	
	ge25519_scalarmult_base(&A, &a);
	ge25519_pack(pk, &A);

	if (memcmp(pk, &halfkey[HEADER_HALFKEYLEN + SECRET_LEN], PUBLIC_LEN) != 0) {
		fprintf(stderr,"Didn't get the expected public key. You probably didn't use the right basekey(s).\n");
		exit(1);
	}

	char *newpath = malloc(strlen(minedpath) + strlen("hs_ed25519_secret_key") + 1);
	strcpy(newpath, minedpath);
	char *slash = strrchr(newpath, '/');
	slash = slash ? slash + 1 : newpath;
	strcpy(slash, "hs_ed25519_secret_key");
	printf("saving to %s\n", newpath);

	fp = fopen(newpath, "w");
	if (!fp) {
		perror("couldn't open");
		exit(1);
	}
	if (fwrite(result, sizeof result, 1, fp) != 1) {
		perror("failed to write hs_ed25519_secret_key");
		exit(1);
	}
	fclose(fp);
}
#include "ed25519/ed25519_impl_post.h"

int main(int argc,char **argv)
{
	const char *outfile = 0;
	const char *infile = 0;
	const char *onehostname = 0;
	const char *arg;
	int ignoreargs = 0;
	int dirnameflag = 0;
	int numthreads = 0;
	enum worker_type wt = WT_BATCH;
	int yamlinput = 0;
#ifdef PASSPHRASE
	int deterministic = 0;
#endif
	int outfileoverwrite = 0;
	struct threadvec threads;
#ifdef STATISTICS
	struct statsvec stats;
	struct tstatsvec tstats;
	u64 reportdelay = 0;
	int realtimestats = 1;
#endif
	int tret;
	int basekeys = 0;

	if (sodium_init() < 0) {
		fprintf(stderr,"sodium_init() failed\n");
		return 1;
	}
	worker_init();
	filters_init();

	setvbuf(stderr,0,_IONBF,0);
	fout = stdout;

	const char *progname = argv[0];
	if (argc <= 1) {
		printhelp(stderr,progname);
		exit(1);
	}
	argc--; argv++;

	while (argc--) {
		arg = *argv++;
		if (!ignoreargs && *arg == '-') {
			int numargit = 0;
		nextarg:
			++arg;
			++numargit;
			if (*arg == '-') {
				if (numargit > 1) {
					fprintf(stderr,"unrecognised argument: -\n");
					exit(1);
				}
				++arg;
				if (!*arg)
					ignoreargs = 1;
				else if (!strcmp(arg,"help") || !strcmp(arg,"usage")) {
					printhelp(stdout,progname);
					exit(0);
				}
				else if (!strcmp(arg,"version")) {
					printversion();
					exit(0);
				}
				else if (!strcmp(arg,"combine")) {
					combine(argc,argv);
					exit(0);
				}
				else if (!strcmp(arg,"genbase")) {
					if (argc != 2) {
						printhelp(stdout,progname);
						exit(0);
					}
					genbase(argv[0],argv[1]);
					exit(0);
				}
				else if (!strcmp(arg,"basekey")) {
					if (argc--) {
						u8 base_pk[32];
						FILE *fp = fopen(*argv++, "r");
						if (!fp) {
							perror("couldn't open basekey");
							exit(1);
						}
						if (fread(base_pk, 1, HEADER_BASEPKLEN, fp) != HEADER_BASEPKLEN) {
							perror("read");
							exit(1);
						}
						if (memcmp(base_pk, HEADER_BASEPK, HEADER_BASEPKLEN) != 0) {
							fprintf(stderr, "\"%s\" isn't a valid base public key.\n", argv[-1]);
							exit(1);
						}
						if (fread(base_pk, 1, sizeof base_pk, fp) != sizeof base_pk) {
							perror("read");
							exit(1);
						}
						fclose(fp);
						ed25519_pubkey_addbase(base_pk);
						basekeys++;
					} else {
						e_additional();
					}
				}
				else if (!strcmp(arg,"rawyaml"))
					yamlraw = 1;
#ifdef PASSPHRASE
				else if (!strcmp(arg,"checkpoint")) {
					if (argc--)
						checkpointfile = *argv++;
					else
						e_additional();
				}
#endif // PASSPHRASE
				else {
					fprintf(stderr,"unrecognised argument: --%s\n",arg);
					exit(1);
				}
				numargit = 0;
			}
			else if (*arg == 0) {
				if (numargit == 1)
					ignoreargs = 1;
				continue;
			}
			else if (*arg == 'h') {
				printhelp(stdout,progname);
				exit(0);
			}
			else if (*arg == 'V') {
				printversion();
				exit(0);
			}
			else if (*arg == 'f') {
				if (argc--) {
					if (!loadfilterfile(*argv++))
						exit(1);
				}
				else
					e_additional();
			}
			else if (*arg == 'D') {
#ifndef PCRE2FILTER
				wantdedup = 1;
#else
				fprintf(stderr,"WARNING: deduplication isn't supported with regex filters\n");
#endif
			}
			else if (*arg == 'q')
				++quietflag;
			else if (*arg == 'x')
				fout = 0;
			else if (*arg == 'v')
				verboseflag = 1;
			else if (*arg == 'o') {
				outfileoverwrite = 0;
				if (argc--)
					outfile = *argv++;
				else
					e_additional();
			}
			else if (*arg == 'O') {
				outfileoverwrite = 1;
				if (argc--)
					outfile = *argv++;
				else
					e_additional();
			}
			else if (*arg == 'F')
				dirnameflag = 1;
			else if (*arg == 'd') {
				if (argc--)
					setworkdir(*argv++);
				else
					e_additional();
			}
			else if (*arg == 't' || *arg == 'j') {
				if (argc--)
					numthreads = atoi(*argv++);
				else
					e_additional();
			}
			else if (*arg == 'n') {
				if (argc--)
					numneedgenerate = (size_t)atoll(*argv++);
				else
					e_additional();
			}
			else if (*arg == 'N') {
				if (argc--)
					numwords = atoi(*argv++);
				else
					e_additional();
			}
			else if (*arg == 'Z')
				wt = WT_SLOW;
			else if (*arg == 'z')
				wt = WT_FAST;
			else if (*arg == 'B')
				wt = WT_BATCH;
			else if (*arg == 's') {
#ifdef STATISTICS
				reportdelay = 10000000;
#else
				e_nostatistics();
#endif
			}
			else if (*arg == 'S') {
#ifdef STATISTICS
				if (argc--)
					reportdelay = (u64)atoll(*argv++) * 1000000;
				else
					e_additional();
#else
				e_nostatistics();
#endif
			}
			else if (*arg == 'T') {
#ifdef STATISTICS
				realtimestats = 0;
#else
				e_nostatistics();
#endif
			}
			else if (*arg == 'y')
				yamloutput = 1;
			else if (*arg == 'Y') {
				yamlinput = 1;
				if (argc) {
					--argc;
					infile = *argv++;
					if (!*infile)
						infile = 0;
					if (argc) {
						--argc;
						onehostname = *argv++;
						if (!*onehostname)
							onehostname = 0;
						if (onehostname && strlen(onehostname) != ONION_LEN) {
							fprintf(stderr,"bad onion argument length\n");
							exit(1);
						}
					}
				}
			}
#ifdef PASSPHRASE
			else if (*arg == 'p') {
				if (argc--) {
					setpassphrase(*argv++);
					deterministic = 1;
				}
				else
					e_additional();
			}
			else if (*arg == 'P') {
				const char *pass = getenv("PASSPHRASE");
				if (!pass) {
					fprintf(stderr,"store passphrase in PASSPHRASE environment variable\n");
					exit(1);
				}
				setpassphrase(pass);
				deterministic = 1;
			}
#endif // PASSPHRASE
			else {
				fprintf(stderr,"unrecognised argument: -%c\n",*arg);
				exit(1);
			}
			if (numargit)
				goto nextarg;
		}
		else
			filters_add(arg);
	}

	if (yamlinput && yamloutput) {
		fprintf(stderr,"both -y and -Y does not make sense\n");
		exit(1);
	}

	if (yamlraw && !yamlinput && !yamloutput) {
		fprintf(stderr,"--rawyaml requires either -y or -Y to do anything\n");
		exit(1);
	}

	if (yamloutput && 0 < basekeys) {
		fprintf(stderr,"-y is incompatible with --basekey\n");
		exit(1);
	}

#ifdef PASSPHRASE
	if (checkpointfile && !deterministic) {
		fprintf(stderr,"--checkpoint requires passphrase\n");
		exit(1);
	}
#endif

	if (outfile) {
		fout = fopen(outfile,!outfileoverwrite ? "a" : "w");
		if (!fout) {
			perror("failed to open output file");
			exit(1);
		}
	}

	if (!fout && yamloutput) {
		fprintf(stderr,"nil output with yaml mode does not make sense\n");
		exit(1);
	}

	if (workdir)
		createdir(workdir,1);

	direndpos = workdirlen;
	onionendpos = workdirlen + ONION_LEN;

	if (!dirnameflag) {
		printstartpos = direndpos;
		printlen = ONION_LEN + 1; // + '\n'
	} else {
		printstartpos = 0;
		printlen = onionendpos + 1; // + '\n'
	}

	if (yamlinput) {
		char *sname = makesname();
		FILE *fin = stdin;
		if (infile) {
			fin = fopen(infile,"r");
			if (!fin) {
				fprintf(stderr,"failed to open input file\n");
				return 1;
			}
		}
		tret = yamlin_parseandcreate(fin,sname,onehostname,yamlraw);
		if (infile) {
			fclose(fin);
			fin = 0;
		}
		free(sname);

		if (tret)
			return tret;

		goto done;
	}

	filters_prepare();

	filters_print();

#ifdef STATISTICS
	if (!filters_count() && !reportdelay)
#else
	if (!filters_count())
#endif
		return 0;

#ifdef EXPANDMASK
	if (numwords > 1 && flattened)
		fprintf(stderr,"WARNING: -N switch will produce bogus results because we can't know filter width. reconfigure with --enable-besort and recompile.\n");
#endif

	if (yamloutput)
		yamlout_init();

	pthread_mutex_init(&keysgenerated_mutex,0);
	pthread_mutex_init(&fout_mutex,0);
#ifdef PASSPHRASE
	pthread_mutex_init(&determseed_mutex,0);
#endif

	if (numthreads <= 0) {
		numthreads = cpucount();
		if (numthreads <= 0)
			numthreads = 1;
	}
	if (!quietflag)
		fprintf(stderr,"using %d %s\n",
			numthreads,numthreads == 1 ? "thread" : "threads");

#ifdef PASSPHRASE
	if (deterministic) {
		if (!quietflag && numneedgenerate != 1)
			fprintf(stderr,"CAUTION: avoid using keys generated with same password for unrelated services, as single leaked key may help attacker to regenerate related keys.\n");
		if (checkpointfile) {
			memcpy(orig_determseed,determseed,sizeof(determseed));
			// Read current checkpoint position if file exists
			FILE *checkout = fopen(checkpointfile,"r");
			if (checkout) {
				u8 checkpoint[SEED_LEN];
				if(fread(checkpoint,1,SEED_LEN,checkout) != SEED_LEN) {
					fprintf(stderr,"failed to read checkpoint file\n");
					exit(1);
				}
				fclose(checkout);

				// Apply checkpoint to determseed
				for (int i = 0; i < SEED_LEN; i++)
					determseed[i] += checkpoint[i];
			}
		}
	}
#endif

	signal(SIGTERM,termhandler);
	signal(SIGINT,termhandler);

	VEC_INIT(threads);
	VEC_ADDN(threads,numthreads);
#ifdef STATISTICS
	VEC_INIT(stats);
	VEC_ADDN(stats,numthreads);
	VEC_ZERO(stats);
	VEC_INIT(tstats);
	VEC_ADDN(tstats,numthreads);
	VEC_ZERO(tstats);
#endif

	pthread_attr_t tattr,*tattrp = &tattr;
	tret = pthread_attr_init(tattrp);
	if (tret) {
		perror("pthread_attr_init");
		tattrp = 0;
	}
	else {
		// 256KiB plus whatever batch stuff uses if in batch mode
		size_t ss = 256 << 10;
		if (wt == WT_BATCH)
			ss += worker_batch_memuse();
		// align to 64KiB
		ss = (ss + (64 << 10) - 1) & ~((64 << 10) - 1);
		//printf("stack size: " FSZ "\n",ss);
		tret = pthread_attr_setstacksize(tattrp,ss);
		if (tret)
			perror("pthread_attr_setstacksize");
	}

	for (size_t i = 0;i < VEC_LENGTH(threads);++i) {
		void *tp = 0;
#ifdef STATISTICS
		tp = &VEC_BUF(stats,i);
#endif
		tret = pthread_create(
			&VEC_BUF(threads,i),
			tattrp,
#ifdef PASSPHRASE
			deterministic
				? (wt == WT_BATCH
					? CRYPTO_NAMESPACE(worker_batch_pass)
					: CRYPTO_NAMESPACE(worker_fast_pass))
				:
#endif
			wt == WT_BATCH
				? CRYPTO_NAMESPACE(worker_batch)
				:
			wt == WT_FAST
				? CRYPTO_NAMESPACE(worker_fast)
				: CRYPTO_NAMESPACE(worker_slow),
			tp
		);
		if (tret) {
			fprintf(stderr,"error while making " FSZ "th thread: %s\n",i,strerror(tret));
			exit(1);
		}
	}

	if (tattrp) {
		tret = pthread_attr_destroy(tattrp);
		if (tret)
			perror("pthread_attr_destroy");
	}

#ifdef PASSPHRASE
	pthread_t checkpoint_thread;

	if (checkpointfile) {
		tret = pthread_create(&checkpoint_thread,NULL,checkpointworker,NULL);
		if (tret) {
			fprintf(stderr,"error while making checkpoint thread: %s\n",strerror(tret));
			exit(1);
		}
	}
#endif

#ifdef STATISTICS
	struct timespec nowtime;
	u64 istarttime,inowtime,ireporttime = 0,elapsedoffset = 0;
	if (clock_gettime(CLOCK_MONOTONIC,&nowtime) < 0) {
		perror("failed to get time");
		exit(1);
	}
	istarttime = (1000000 * (u64)nowtime.tv_sec) + ((u64)nowtime.tv_nsec / 1000);
#endif

	struct timespec ts;
	memset(&ts,0,sizeof(ts));
	ts.tv_nsec = 100000000;
	while (!endwork) {
		if (numneedgenerate && keysgenerated >= numneedgenerate) {
			endwork = 1;
			break;
		}
		nanosleep(&ts,0);

#ifdef STATISTICS
		clock_gettime(CLOCK_MONOTONIC,&nowtime);
		inowtime = (1000000 * (u64)nowtime.tv_sec) + ((u64)nowtime.tv_nsec / 1000);
		u64 sumcalc = 0,sumsuccess = 0,sumrestart = 0;
		for (int i = 0;i < numthreads;++i) {
			u32 newt,tdiff;
			// numcalc
			newt = VEC_BUF(stats,i).numcalc.v;
			tdiff = newt - VEC_BUF(tstats,i).oldnumcalc;
			VEC_BUF(tstats,i).oldnumcalc = newt;
			VEC_BUF(tstats,i).numcalc += (u64)tdiff;
			sumcalc += VEC_BUF(tstats,i).numcalc;
			// numsuccess
			newt = VEC_BUF(stats,i).numsuccess.v;
			tdiff = newt - VEC_BUF(tstats,i).oldnumsuccess;
			VEC_BUF(tstats,i).oldnumsuccess = newt;
			VEC_BUF(tstats,i).numsuccess += (u64)tdiff;
			sumsuccess += VEC_BUF(tstats,i).numsuccess;
			// numrestart
			newt = VEC_BUF(stats,i).numrestart.v;
			tdiff = newt - VEC_BUF(tstats,i).oldnumrestart;
			VEC_BUF(tstats,i).oldnumrestart = newt;
			VEC_BUF(tstats,i).numrestart += (u64)tdiff;
			sumrestart += VEC_BUF(tstats,i).numrestart;
		}
		if (reportdelay && (!ireporttime || (i64)(inowtime - ireporttime) >= (i64)reportdelay)) {
			if (ireporttime)
				ireporttime += reportdelay;
			else
				ireporttime = inowtime;
			if (!ireporttime)
				ireporttime = 1;

			double calcpersec = (1000000.0 * sumcalc) / (inowtime - istarttime);
			double succpersec = (1000000.0 * sumsuccess) / (inowtime - istarttime);
			double restpersec = (1000000.0 * sumrestart) / (inowtime - istarttime);
			fprintf(stderr,">calc/sec:%8lf, succ/sec:%8lf, rest/sec:%8lf, elapsed:%5.6lfsec\n",
				calcpersec,succpersec,restpersec,
				(inowtime - istarttime + elapsedoffset) / 1000000.0);

			if (realtimestats) {
				for (int i = 0;i < numthreads;++i) {
					VEC_BUF(tstats,i).numcalc = 0;
					VEC_BUF(tstats,i).numsuccess = 0;
					VEC_BUF(tstats,i).numrestart = 0;
				}
				elapsedoffset += inowtime - istarttime;
				istarttime = inowtime;
			}
		}
		if (sumcalc > U64_MAX / 2) {
			for (int i = 0;i < numthreads;++i) {
				VEC_BUF(tstats,i).numcalc /= 2;
				VEC_BUF(tstats,i).numsuccess /= 2;
				VEC_BUF(tstats,i).numrestart /= 2;
			}
			u64 timediff = (inowtime - istarttime + 1) / 2;
			elapsedoffset += timediff;
			istarttime += timediff;
		}
#endif
	}

	if (!quietflag)
		fprintf(stderr,"waiting for threads to finish...");

	for (size_t i = 0;i < VEC_LENGTH(threads);++i)
		pthread_join(VEC_BUF(threads,i),0);
#ifdef PASSPHRASE
	if (checkpointfile) {
		checkpointer_endwork = 1;
		pthread_join(checkpoint_thread,0);
	}
#endif

	if (!quietflag)
		fprintf(stderr," done.\n");

	if (yamloutput)
		yamlout_clean();

#ifdef PASSPHRASE
	pthread_mutex_destroy(&determseed_mutex);
#endif
	pthread_mutex_destroy(&fout_mutex);
	pthread_mutex_destroy(&keysgenerated_mutex);

done:
	filters_clean();

	if (outfile)
		fclose(fout);

	return 0;
}
