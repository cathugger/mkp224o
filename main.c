#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sodium/randombytes.h>

#include "types.h"
#include "likely.h"
#include "vec.h"
#include "base32.h"
#include "cpucount.h"
#include "keccak.h"
#include "ed25519/ed25519.h"

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

static pthread_mutex_t fout_mutex;
static FILE *fout;
static size_t numneedgenerate = 0;
static pthread_mutex_t keysgenerated_mutex;
static volatile size_t keysgenerated = 0;
static volatile int endwork = 0;

static void termhandler(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		endwork = 1;
		break;
	}
}

// filters stuff

struct binfilter {
	u8 f[PUBLIC_LEN];
	size_t len; // real len minus one
	u8 mask;
} ;

#ifdef INTFILTER
struct intfilter {
	u64 f,m;
} ;
VEC_STRUCT(ifiltervec,struct intfilter) ifilters;
#else
VEC_STRUCT(bfiltervec,struct binfilter) bfilters;
#endif

static void filters_init()
{
#ifdef INTFILTER
	VEC_INIT(ifilters);
#else
	VEC_INIT(bfilters);
#endif
}

static void filters_add(const char *filter)
{
	struct binfilter bf;
	size_t ret, ret2;
#ifdef INTFILTER
	union intconv {
		u64 i;
		u8 b[8];
	} fc,mc;
#endif

	if (!base32_valid(filter,&ret)) {
		fprintf(stderr, "filter \"%s\" is invalid\n", filter);
		return;
	}
	ret = BASE32_FROM_LEN(ret);
	if (!ret)
		return;
#ifdef INTFILTER
	if (ret > 8)
#else
	if (ret > PUBLIC_LEN)
#endif
	{
		fprintf(stderr, "filter \"%s\" is too long\n", filter);
		return;
	}
	ret2 = base32_from(bf.f,&bf.mask,filter);
	assert(ret == ret2);
	//printf("--m:%02X\n", bf.mask);
	bf.len = ret - 1;
#ifdef INTFILTER
	mc.i = 0;
	for (size_t i = 0;i < bf.len;++i)
		mc.b[i] = 0xFF;
	mc.b[bf.len] = bf.mask;
	memcpy(fc.b,bf.f,8);
	fc.i &= mc.i;
	struct intfilter ifltr = {fc.i,mc.i};
	VEC_ADD(ifilters,ifltr);
#else
	VEC_ADD(bfilters,bf);
#endif
}

static void filters_clean()
{
#ifdef INTFILTER
	VEC_FREE(ifilters);
#else
	VEC_FREE(bfilters);
#endif
}

static size_t filters_count()
{
#ifdef INTFILTER
	return VEC_LENGTH(ifilters);
#else
	return VEC_LENGTH(bfilters);
#endif
}

#ifdef INTFILTER

#define FILTERFOR(it) for (it = 0;it < VEC_LENGTH(ifilters);++it)
#define MATCHFILTER(it,pk) ((*(u64 *)(pk) & VEC_BUF(ifilters,it).m) == VEC_BUF(ifilters,it).f)

#else

#define FILTERFOR(it) for (it = 0;it < VEC_LENGTH(bfilters);++it)
#define MATCHFILTER(it,pk) ( \
	memcmp(pk,VEC_BUF(bfilters,it).f,VEC_BUF(bfilters,it).len) == 0 && \
	(pk[VEC_BUF(bfilters,it).len] & VEC_BUF(bfilters,it).mask) == VEC_BUF(bfilters,it).f[VEC_BUF(bfilters,it).len])

#endif

static void loadfilterfile(const char *fname)
{
	char buf[128];
	FILE *f = fopen(fname,"r");
	while (fgets(buf,sizeof(buf),f)) {
		for (char *p = buf;*p;++p) {
			if (*p == '\n') {
				*p = 0;
				break;
			}
		}
		if (*buf && *buf != '#' && memcmp(buf,"//",2) != 0)
			filters_add(buf);
	}
}

static void printfilters()
{
	size_t i,l;
#ifdef INTFILTER
	l = VEC_LENGTH(ifilters);
#else
	l = VEC_LENGTH(bfilters);
#endif
	if (l)
		fprintf(stderr, "filters:\n");
	else
		fprintf(stderr, "no filters defined\n");

	for (i = 0;i < l;++i) {
		char buf0[256],buf1[256];
		u8 bufx[128];
#ifdef INTFILTER
		size_t len = 0;
		u8 *imraw = (u8 *)&VEC_BUF(ifilters,i).m;
		while (len < 8 && imraw[len] != 0x00) ++len;
		u8 mask = imraw[len-1];
		u8 *ifraw = (u8 *)&VEC_BUF(ifilters,i).f;
#else
		size_t len = VEC_BUF(bfilters,i).len + 1;
		u8 mask = VEC_BUF(bfilters,i).mask;
		u8 *ifraw = VEC_BUF(bfilters,i).f;
#endif
		base32_to(buf0,ifraw,len);
		memcpy(bufx,ifraw,len);
		bufx[len - 1] |= ~mask;
		base32_to(buf1,bufx,len);
		char *a = buf0,*b = buf1;
		while (*a && *a == *b)
			++a, ++b;
		*a = 0;
		fprintf(stderr, "\t%s\n",buf0);
	}
}

// statistics, if enabled
#ifdef STATISTICS
struct statstruct {
	union {
		u32 v;
		size_t align;
	} numcalc;
	union {
		u32 v;
		size_t align;
	} numsuccess;
} ;
VEC_STRUCT(statsvec,struct statstruct);

struct tstatstruct {
	u64 numcalc;
	u64 numsuccess;
	u32 oldnumcalc;
	u32 oldnumsuccess;
} ;
VEC_STRUCT(tstatsvec,struct tstatstruct);
#endif


static void onionready(char *sname, const u8 *secret, const u8 *pubonion)
{
	FILE *fh;

	if (endwork)
		return;

	if (numneedgenerate) {
		pthread_mutex_lock(&keysgenerated_mutex);
		if (keysgenerated >= numneedgenerate) {
			pthread_mutex_unlock(&keysgenerated_mutex);
			return;
		}
	}

	if (mkdir(sname,0700) != 0) {
		if (numneedgenerate)
			pthread_mutex_unlock(&keysgenerated_mutex);
		return;
	}

	if (numneedgenerate) {
		++keysgenerated;
		if (keysgenerated >= numneedgenerate)
			endwork = 1;
		pthread_mutex_unlock(&keysgenerated_mutex);
	}

	strcpy(&sname[onionendpos], "/hs_ed25519_secret_key");
	fh = fopen(sname, "wb");
	if (fh) {
		fwrite(secret, skprefixlen + SECRET_LEN, 1, fh);
		fclose(fh);
	}

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

	if (fout) {
		sname[onionendpos] = '\n';
		pthread_mutex_lock(&fout_mutex);
		fwrite(&sname[printstartpos], printlen, 1, fout);
		fflush(fout);
		pthread_mutex_unlock(&fout_mutex);
	}
}

// little endian inc
static void addseed(u8 *seed)
{
	register unsigned int c = 1;
	for (size_t i = 0;i < SEED_LEN;++i) {
		c = (unsigned int)seed[i] + c; seed[i] = c & 0xFF; c >>= 8;
		// unsure if needed
		if (!c) break;
	}
}

static void *dowork(void *task)
{
	union pubonionunion {
		u8 raw[pkprefixlen + PUBLIC_LEN + 32];
		struct {
			u64 prefix[4];
			u64 key[4];
			u64 hash[4];
		} i;
	} pubonion;
	u8 * const pk = &pubonion.raw[pkprefixlen];
	u8 secret[skprefixlen + SECRET_LEN];
	u8 * const sk = &secret[skprefixlen];
	u8 seed[SEED_LEN];
	u8 hashsrc[checksumstrlen + PUBLIC_LEN + 1];
	size_t i;
	char *sname;
#ifdef STATISTICS
	struct statstruct *st = (struct statstruct *)task;
#endif

	memcpy(secret,skprefix,skprefixlen);
	memcpy(pubonion.raw,pkprefix,pkprefixlen);
	// write version later as it will be overwritten by hash
	memcpy(hashsrc,checksumstr,checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = malloc(workdirlen + ONIONLEN + 63 + 1);
	if (workdir)
		memcpy(sname,workdir,workdirlen);

initseed:
	randombytes(seed,sizeof(seed));

again:
	if (unlikely(endwork))
		goto end;

	ed25519_seckey_expand(sk,seed);
	ed25519_pubkey(pk,sk);

#ifdef STATISTICS
	++st->numcalc.v;
#endif

	FILTERFOR(i) {
		if (unlikely(MATCHFILTER(i,pk))) {
#ifdef STATISTICS
			++st->numsuccess.v;
#endif
			// calc checksum
			memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
			FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
			// version byte
			pk[PUBLIC_LEN + 2] = 0x03;
			// base32
			strcpy(base32_to(&sname[direndpos],pk,PUBONION_LEN), ".onion");
			onionready(sname, secret, pubonion.raw);
			goto initseed;
		}
	}
	addseed(seed);
	goto again;

end:
	free(sname);
	return 0;
}

static void addu64toscalar32(u8 *dst,u64 v)
{
	int i;
	u32 c = 0;
	for (i = 0;i < 32;++i) {
		c += *dst + (v & 0xFF); *dst = c & 0xFF; c >>= 8;
		v >>= 8;
		++dst;
	}
}

static void *dofastwork(void *task)
{
	union pubonionunion {
		u8 raw[pkprefixlen + PUBLIC_LEN + 32];
		struct {
			u64 prefix[4];
			u64 key[4];
			u64 hash[4];
		} i;
	} pubonion;
	u8 * const pk = &pubonion.raw[pkprefixlen];
	u8 secret[skprefixlen + SECRET_LEN];
	u8 * const sk = &secret[skprefixlen];
	u8 seed[SEED_LEN];
	u8 hashsrc[checksumstrlen + PUBLIC_LEN + 1];
	ge_p3 ge_public;
	u64 counter;
	size_t i;
	char *sname;
#ifdef STATISTICS
	struct statstruct *st = (struct statstruct *)task;
#endif

	memcpy(secret, skprefix, skprefixlen);
	memcpy(pubonion.raw, pkprefix, pkprefixlen);
	// write version later as it will be overwritten by hash
	memcpy(hashsrc, checksumstr, checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = malloc(workdirlen + ONIONLEN + 63 + 1);
	if (workdir)
		memcpy(sname, workdir, workdirlen);

initseed:
	randombytes(seed,sizeof(seed));
	ed25519_seckey_expand(sk,seed);
	
	ge_scalarmult_base(&ge_public,sk);
	ge_p3_tobytes(pk,&ge_public);
	
	for (counter = 0;counter < U64_MAX-8;counter += 8) {
		ge_p1p1 sum;
		
		if (unlikely(endwork))
			goto end;
		
		FILTERFOR(i) {
			if (unlikely(MATCHFILTER(i,pk))) {
				// found!
				// update secret key with counter
				addu64toscalar32(sk,counter);
				// sanity check
				if (((sk[0] & 248) == sk[0]) && (((sk[31] & 63) | 64) == sk[31])) {
					/* These operations should be a no-op. */
					sk[0] &= 248;
					sk[31] &= 63;
					sk[31] |= 64;
				}
				else goto initseed;
#ifdef STATISTICS
				++st->numsuccess.v;
#endif
				// calc checksum
				memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
				FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
				// version byte
				pk[PUBLIC_LEN + 2] = 0x03;
				// full name
				strcpy(base32_to(&sname[direndpos],pk,PUBONION_LEN),".onion");
				onionready(sname,secret,pubonion.raw);
				// don't reuse same seed
				goto initseed;
			}
		}

		// next
		ge_add(&sum, &ge_public,&ge_eightpoint);
		ge_p1p1_to_p3(&ge_public,&sum);
		ge_p3_tobytes(pk,&ge_public);
#ifdef STATISTICS
		++st->numcalc.v;
#endif
	}
	goto initseed;

end:
	free(sname);
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
		"\t-j numthreads  - same as -t\n"
		"\t-n numkeys  - specify number of keys (default - 0 - unlimited)\n"
		"\t-z  - use faster key generation method. this is now default\n"
		"\t-Z  - use slower key generation method\n"
		"\t-s  - print statistics each 10 seconds\n"
		"\t-S t  - print statistics every specified ammount of seconds\n"
		"\t-T  - do not reset statistics counters when printing\n"
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
		fprintf(stderr,"set workdir: %s\n",workdir);
}

VEC_STRUCT(threadvec, pthread_t);

int main(int argc,char **argv)
{
	char *outfile = 0;
	const char *arg;
	int ignoreargs = 0;
	int dirnameflag = 0;
	int numthreads = 0;
	int fastkeygen = 1;
	struct threadvec threads;
#ifdef STATISTICS
	struct statsvec stats;
	struct tstatsvec tstats;
	u64 reportdelay = 0;
	int realtimestats = 1;
#endif
	int tret;

	ge_initeightpoint();
	filters_init();

	fout = stdout;
	pthread_mutex_init(&keysgenerated_mutex, 0);
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
			else if (*arg == 't' || *arg == 'j') {
				if (argc--)
					numthreads = atoi(*argv++);
				else {
					fprintf(stderr, "additional argument required\n");
					exit(1);
				}
			}
			else if (*arg == 'n') {
				if (argc--)
					numneedgenerate = (size_t)atoll(*argv++);
				else {
					fprintf(stderr, "additional argument required\n");
					exit(1);
				}
			}
			else if (*arg == 'Z')
				fastkeygen = 0;
			else if (*arg == 'z')
				fastkeygen = 1;
			else if (*arg == 's') {
#ifdef STATISTICS
				reportdelay = 10000000;
#else
				fprintf(stderr,"statistics support not compiled in\n");
				exit(1);
#endif
			}
			else if (*arg == 'S') {
#ifdef STATISTICS
				if (argc--)
					reportdelay = (u64)atoll(*argv++) * 1000000;
				else {
					fprintf(stderr, "additional argument required\n");
					exit(1);
				}
#else
				fprintf(stderr,"statistics support not compiled in\n");
				exit(1);
#endif
			}
			else if (*arg == 'T') {
#ifdef STATISTICS
				realtimestats = 0;
#else
				fprintf(stderr,"statistics support not compiled in\n");
				exit(1);
#endif
			}
			else {
				fprintf(stderr, "unrecognised argument: -%c\n", *arg);
				exit(1);
			}
			if (numargit)
				goto nextarg;
		}
		else filters_add(arg);
	}

	if (!quietflag)
		printfilters();

	if (!filters_count())
		return 0;

	if (outfile)
		fout = fopen(outfile, "w");

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
		numthreads = cpucount();
		if (numthreads <= 0)
			numthreads = 1;
	}

	signal(SIGTERM,termhandler);
	signal(SIGINT,termhandler);

	VEC_INIT(threads);
	VEC_ADDN(threads,pthread_t,numthreads);
#ifdef STATISTICS
	VEC_INIT(stats);
	VEC_INIT(tstats);
	VEC_ADDN(stats,struct statstruct,numthreads);
	VEC_ADDN(tstats,struct tstatstruct,numthreads);
	memset(&VEC_BUF(stats,0),0,sizeof(struct statstruct) * VEC_LENGTH(stats));
	memset(&VEC_BUF(tstats,0),0,sizeof(struct tstatstruct) * VEC_LENGTH(tstats));
#endif

	for (size_t i = 0;i < VEC_LENGTH(threads);++i) {
		void *tp = 0;
#ifdef STATISTICS
		tp = &VEC_BUF(stats,i);
#endif
		tret = pthread_create(&VEC_BUF(threads,i),0,fastkeygen ? dofastwork : dowork,tp);
		if (tret) {
			fprintf(stderr,"error while making %dth thread: %d\n",(int)i,tret);
			exit(1);
		}
	}

#ifdef STATISTICS
	struct timespec nowtime;
	u64 istarttime,inowtime,ireporttime = 0,elapsedoffset = 0;
	if (clock_gettime(CLOCK_MONOTONIC,&nowtime) < 0) {
		fprintf(stderr, "failed to get time\n");
		exit(1);
	}
	istarttime = (1000000 * (u64)nowtime.tv_sec) + (nowtime.tv_nsec / 1000);
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
		inowtime = (1000000 * (u64)nowtime.tv_sec) + (nowtime.tv_nsec / 1000);
		u64 sumcalc = 0,sumsuccess = 0;
		for (size_t i = 0;i < numthreads;++i) {
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
		}
		if (reportdelay && (!ireporttime || inowtime - ireporttime >= reportdelay)) {
			if (ireporttime)
				ireporttime += reportdelay;
			else
				ireporttime = inowtime;
			if (!ireporttime)
				ireporttime = 1;

			double calcpersec = (1000000.0 * sumcalc) / (inowtime - istarttime);
			double successpersec = (1000000.0 * sumsuccess) / (inowtime - istarttime);
			fprintf(stderr,">calc/sec:%8lf, success/sec:%8lf, elapsed:%5.6lfsec\n",calcpersec,successpersec,(inowtime - istarttime + elapsedoffset) / 1000000.0);

			if (realtimestats) {
				for (size_t i = 0;i < numthreads;++i) {
					VEC_BUF(tstats,i).numcalc = 0;
					VEC_BUF(tstats,i).numsuccess = 0;
				}
				elapsedoffset += inowtime - istarttime;
				istarttime = inowtime;
			}
		}
		if (sumcalc > U64_MAX / 2) {
			for (size_t i = 0;i < numthreads;++i) {
				VEC_BUF(tstats,i).numcalc /= 2;
				VEC_BUF(tstats,i).numsuccess /= 2;
			}
			u64 timediff = (inowtime - istarttime + 1) / 2;
			elapsedoffset += timediff;
			istarttime += timediff;
		}
#endif
	}

	if (!quietflag)
		fprintf(stderr, "waiting for threads to finish...\n");
	for (size_t i = 0;i < VEC_LENGTH(threads);++i)
		pthread_join(VEC_BUF(threads,i),0);
	if (!quietflag)
		fprintf(stderr, "done, quitting\n");

	pthread_mutex_destroy(&keysgenerated_mutex);
	pthread_mutex_destroy(&fout_mutex);
	filters_clean();

	if (outfile)
		fclose(fout);

	return 0;
}
