#ifdef __linux__
#define _POSIX_C_SOURCE 200112L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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
static int numwords = 1;
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

#ifdef INTFILTER
#ifdef BINSEARCH
#ifndef BESORT
#define OMITMASK
#endif
#endif
#endif

#ifdef OMITMASK
#define EXPANDMASK
#endif

#ifndef BINFILTERLEN
#define BINFILTERLEN PUBLIC_LEN
#endif
struct binfilter {
	u8 f[BINFILTERLEN];
	size_t len; // real len minus one
	u8 mask;
} ;

#ifdef INTFILTER
struct intfilter {
	IFT f;
# ifndef OMITMASK
	IFT m;
# endif
} ;
VEC_STRUCT(ifiltervec,struct intfilter) ifilters;
# ifdef OMITMASK
IFT ifiltermask;
# endif // BINSEARCH
#else // INTFILTER
VEC_STRUCT(bfiltervec,struct binfilter) bfilters;
#endif // INTFILTER

static void filters_init()
{
#ifdef INTFILTER
	VEC_INIT(ifilters);
#else
	VEC_INIT(bfilters);
#endif
}

#ifdef INTFILTER

static void filter_sort(int (*compf)(const void *,const void *))
{
	qsort(&VEC_BUF(ifilters,0),VEC_LENGTH(ifilters),sizeof(struct intfilter),compf);
}

static inline size_t filter_len(size_t i)
{
# ifndef OMITMASK
	const u8 *m = (const u8 *)&VEC_BUF(ifilters,i).m;
# else // OMITMASK
	const u8 *m = (const u8 *)&ifiltermask;
# endif // OMITMASK
	size_t c = 0;
	for (size_t j = 0;;) {
		u8 v = m[j];
		for (size_t k = 0;;) {
			if (!v)
				return c;
			++c;
			if (++k >= 8)
				break;
			v <<= 1;
		}
		if (++j >= sizeof(IFT))
			break;
	}
	return c;
}

# ifdef OMITMASK

static int filter_compare(const void *p1,const void *p2)
{
	if (((const struct intfilter *)p1)->f < ((const struct intfilter *)p2)->f)
		return -1;
	if (((const struct intfilter *)p1)->f > ((const struct intfilter *)p2)->f)
		return 1;
	return 0;
}

#  ifdef EXPANDMASK

/*
 * raw representation -- FF.FF.F0.00
 * big endian         -- 0xFFFFF000
 * little endian      -- 0x00F0FFFF
 * b: 0xFFffF000 ^ 0xFFff0000 -> 0x0000F000
 *   0x0000F000 + 1 -> 0x0000F001
 *   0x0000F000 & 0x0000F001 -> 0x0000F000 <- shifted mask
 *   0x0000F000 ^ 0x0000F000 -> 0x00000000 <- direct mask
 *   0x0000F000 ^ 0x00000000 -> 0x0000F000 <- shifted mask
 * l: 0x00f0FFff ^ 0x0000FFff -> 0x00f00000
 *   0x00f00000 + 1 -> 0x00f00001
 *   0x00f00000 & 0x00f00001 -> 0x00f00000 <- shifted mask
 *   0x00f00000 ^ 0x00f00000 -> 0x00000000 <- direct mask
 *   0x00f00000 ^ 0x00000000 -> 0x00f00000 <- shifted mask
 *
 * b: 0xFFffFFff ^ 0xF0000000 -> 0x0FffFFff
 *   0x0FffFFff + 1 -> 0x10000000
 *   0x0FffFFff & 0x10000000 -> 0x00000000 <- shifted mask
 *   0x0FffFFff ^ 0x00000000 -> 0x0FffFFff <- direct mask
 *   0x0FffFFff ^ 0x0FffFFff -> 0x00000000 <- shifted mask
 * l: 0xFFffFFff ^ 0x000000f0 -> 0xFFffFF0f
 *   0xFFffFF0f + 1 -> 0xFFffFF10
 *   0xFFffFF0f & 0xFFffFF10 -> 0xFFffFF00 <- shifted mask
 *   0xFFffFF0f ^ 0xFFffFF00 -> 0x0000000f <- direct mask
 *   0xFFffFF0f ^ 0x0000000f -> 0xFFffFF00 <- shifted mask
 *
 * essentially, we have to make direct mask + shifted mask bits worth of information
 * and then split it into 2 parts
 * we do not need absolute shifted mask shifting value, just relative to direct mask
 * 0x0sss00dd - shifted & direct mask combo
 * 0x000sssdd - combined mask
 * 8 - relshiftval
 * generate values from 0x00000000 to 0x000sssdd
 * for each value, realmask <- (val & 0x000000dd) | ((val & 0x000sss00) << relshiftval)
 * or..
 * realmask <- (val & 0x000000dd) | ((val << relshiftval) & 0x0sss0000)
 * ...
 * above method doesn't work in some cases. better way:
 * l: 0x80ffFFff ^ 0x00f0FFff -> 0x800f0000
 *   0x800f0000 >> 16 -> 0x0000800f
 *   0x0000800f + 1 -> 0x00008010
 *   0x0000800f & 0x00008010 -> 0x00008000 <- smask
 *   0x0000800f ^ 0x00008000 -> 0x0000000f <- dmask
 */

#define EXPVAL(init,j,dmask,smask,ishift,rshift) \
	((init) | ((((j) & (dmask)) | (((j) << (rshift)) & (smask))) << (ishift)))
// add expanded set of values
// allocates space on its own
static void ifilter_addexpanded(
	struct intfilter *ifltr,
	IFT dmask,IFT smask,IFT cmask,
	int ishift,int rshift)
{
	size_t i = VEC_LENGTH(ifilters);
	VEC_ADDN(ifilters,cmask + 1);
	for (size_t j = 0;;++j) {
		VEC_BUF(ifilters,i + j).f = EXPVAL(ifltr->f,j,dmask,smask,ishift,rshift);
		if (j == cmask)
			break;
	}
}

// expand existing stuff
// allocates needed stuff on its own
static void ifilter_expand(IFT dmask,IFT smask,IFT cmask,int ishift,int rshift)
{
	size_t len = VEC_LENGTH(ifilters);
	VEC_ADDN(ifilters,cmask * len);
	size_t esz = cmask + 1; // size of expanded elements
	for (size_t i = len - 1;;--i) {
		for (IFT j = 0;;++j) {
			VEC_BUF(ifilters,i * esz + j).f = EXPVAL(VEC_BUF(ifilters,i).f,j,dmask,smask,ishift,rshift);
			if (j == cmask)
				break;
		}
		if (i == 0)
			break;
	}
}

static inline void ifilter_addflatten(struct intfilter *ifltr,IFT mask)
{
	if (VEC_LENGTH(ifilters) == 0) {
		// simple
		VEC_ADD(ifilters,*ifltr);
		ifiltermask = mask;
		return;
	}
	if (ifiltermask == mask) {
		// lucky
		VEC_ADD(ifilters,*ifltr);
		return;
	}
	IFT cross = ifiltermask ^ mask;
	int ishift = 0;
	while ((cross & 1) == 0) {
		++ishift;
		cross >>= 1;
	}
	IFT smask = cross & (cross + 1); // shift mask
	IFT dmask = cross ^ smask; // direct mask
	IFT cmask; // combined mask
	int rshift = 0; // relative shift
	while (cmask = (smask >> rshift) | dmask,(cmask & (cmask + 1)) != 0)
		++rshift;
	// preparations done
	if (ifiltermask > mask) {
		// already existing stuff has more precise mask than we
		// so we need to expand our stuff
		ifilter_addexpanded(ifltr,dmask,smask,cmask,ishift,rshift);
	}
	else {
		ifiltermask = mask;
		ifilter_expand(dmask,smask,cmask,ishift,rshift);
		VEC_ADD(ifilters,*ifltr);
	}
}

#  endif // EXPANDMASK

# else // OMITMASK

/*
 * struct intfilter layout: filter,mask
 * stuff is compared in big-endian way, so memcmp
 * filter needs to be compared first
 * if its equal, mask needs to be compared
 * memcmp is aplicable there too
 * due to struct intfilter layout, it all can be stuffed into one memcmp call
 */
static int filter_compare(const void *p1,const void *p2)
{
	return memcmp(p1,p2,sizeof(struct intfilter));
}

# endif // OMITMASK
#else // INTFILTER

static inline size_t filter_len(size_t i)
{
	size_t c = VEC_BUF(bfilters,i).len * 8;
	u8 v = VEC_BUF(bfilters,i).mask;
	for (size_t k = 0;;) {
		if (!v)
			return c;
		++c;
		if (++k >= 8)
			return c;
		v <<= 1;
	}
}

static void filter_sort(int (*compf)(const void *,const void *))
{
	qsort(&VEC_BUF(bfilters,0),VEC_LENGTH(bfilters),sizeof(struct binfilter),compf);
}

static int filter_compare(const void *p1,const void *p2)
{
	const struct binfilter *b1 = (const struct binfilter *)p1;
	const struct binfilter *b2 = (const struct binfilter *)p2;
	size_t l = b1->len <= b2->len ? b1->len : b2->len;
	int cmp = memcmp(b1->f,b2->f,l);
	if (cmp)
		return cmp;
	if (b1->len < b2->len)
		return -1;
	if (b1->len > b2->len)
		return 1;
	if (b1->mask < b2->mask)
		return -1;
	if (b1->mask > b2->mask)
		return 1;
	return 0;
}

#endif // INTFILTER

static void filters_add(const char *filter)
{
	struct binfilter bf;
	size_t ret;
#ifdef INTFILTER
	union intconv {
		IFT i;
		u8 b[sizeof(IFT)];
	} fc,mc;
#endif

	// skip regex start symbol. we do not support regex tho
	if (*filter == '^')
		++filter;

	memset(&bf,0,sizeof(bf));

	if (!base32_valid(filter,&ret)) {
		fprintf(stderr,"filter \"%s\" is invalid\n",filter);
		return;
	}
	ret = BASE32_FROM_LEN(ret);
	if (!ret)
		return;
#ifdef INTFILTER
	if (ret > sizeof(IFT))
#else
	if (ret > sizeof(bf.f))
#endif
	{
		fprintf(stderr,"filter \"%s\" is too long\n",filter);
		return;
	}
	base32_from(bf.f,&bf.mask,filter);
	bf.len = ret - 1;
#ifdef INTFILTER
	mc.i = 0;
	for (size_t i = 0;i < bf.len;++i)
		mc.b[i] = 0xFF;
	mc.b[bf.len] = bf.mask;
	memcpy(fc.b,bf.f,sizeof(fc.b));
	fc.i &= mc.i;
	struct intfilter ifltr = {
		.f = fc.i,
# ifndef OMITMASK
		.m = mc.i,
# endif
	};
# ifdef OMITMASK
	ifilter_addflatten(&ifltr,mc.i);
# else // OMITMASK
	VEC_ADD(ifilters,ifltr);
# endif // OMITMASK
#else // INTFILTER
	VEC_ADD(bfilters,bf);
#endif // INTFILTER
}

static void filters_prepare()
{
	if (!quietflag)
		fprintf(stderr,"sorting filters...");
	filter_sort(&filter_compare);
	if (!quietflag)
		fprintf(stderr," done.\n");
	// TODO remove duplicates
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

#ifdef STATISTICS
#define ADDNUMSUCCESS ++st->numsuccess.v
#else
#define ADDNUMSUCCESS do ; while (0)
#endif

#ifdef INTFILTER

# ifndef BINSEARCH

#define MATCHFILTER(it,pk) \
	((*(IFT *)(pk) & VEC_BUF(ifilters,it).m) == VEC_BUF(ifilters,it).f)

#define DOFILTER(it,pk,code) \
do { \
	for (it = 0;it < VEC_LENGTH(ifilters);++it) { \
		if (unlikely(MATCHFILTER(it,pk))) { \
			code; \
			break; \
		} \
	} \
} while (0)

# else // BINSEARCH

#  ifdef OMITMASK

#define DOFILTER(it,pk,code) \
do { \
	register IFT maskedpk = *(IFT *)(pk) & ifiltermask; \
	for (size_t down = 0,up = VEC_LENGTH(ifilters);down < up;) { \
		it = (up + down) / 2; \
		if (maskedpk < VEC_BUF(ifilters,it).f) \
			up = it; \
		else if (maskedpk > VEC_BUF(ifilters,it).f) \
			down = it + 1; \
		else { \
			code; \
			break; \
		} \
	} \
} while (0)

#  else // OMITMASK

#define DOFILTER(it,pk,code) \
do { \
	for (size_t down = 0,up = VEC_LENGTH(ifilters);down < up;) { \
		it = (up + down) / 2; \
		IFT maskedpk = *(IFT *)(pk) & VEC_BUF(ifilters,it).m; \
		register int cmp = memcmp(&maskedpk,&VEC_BUF(ifilters,it).f,sizeof(IFT)); \
		if (cmp < 0) \
			up = it; \
		else if (cmp > 0) \
			down = it + 1; \
		else { \
			code; \
			break; \
		} \
	} \
} while (0)

#  endif // OMITMASK

# endif // BINSEARCH

#else // INTFILTER

# ifndef BINSEARCH

#define MATCHFILTER(it,pk) ( \
	memcmp(pk,VEC_BUF(bfilters,it).f,VEC_BUF(bfilters,it).len) == 0 && \
	(pk[VEC_BUF(bfilters,it).len] & VEC_BUF(bfilters,it).mask) == VEC_BUF(bfilters,it).f[VEC_BUF(bfilters,it).len])

#define DOFILTER(it,pk,code) \
do { \
	for (it = 0;it < VEC_LENGTH(bfilters);++it) { \
		if (unlikely(MATCHFILTER(it,pk))) { \
			code; \
			break; \
		} \
	} \
} while (0)

# else // BINSEARCH

#define DOFILTER(it,pk,code) \
do { \
	for (size_t down = 0,up = VEC_LENGTH(bfilters);down < up;) { \
		it = (up + down) / 2; \
		{ \
			register int filterdiff = memcmp(pk,VEC_BUF(bfilters,it).f,VEC_BUF(bfilters,it).len); \
			if (filterdiff < 0) { \
				up = it; \
				continue; \
			} \
			if (filterdiff > 0) { \
				down = it + 1; \
				continue; \
			} \
		} \
		if ((pk[VEC_BUF(bfilters,it).len] & VEC_BUF(bfilters,it).mask) < \
			VEC_BUF(bfilters,it).f[VEC_BUF(bfilters,it).len]) \
		{ \
			up = it; \
			continue; \
		} \
		if ((pk[VEC_BUF(bfilters,it).len] & VEC_BUF(bfilters,it).mask) > \
			VEC_BUF(bfilters,it).f[VEC_BUF(bfilters,it).len]) \
		{ \
			down = it + 1; \
			continue; \
		} \
		{ \
			code; \
			break; \
		} \
	} \
} while (0)

# endif // BINSEARCH

#endif // INTFILTER

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

static void filters_print()
{
	if (quietflag)
		return;
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

		if (i >= 20) {
			fprintf(stderr,"[another %llu filters not shown]\n",(unsigned long long)(filters_count() - 20));
			break;
		}

#ifdef INTFILTER
		size_t len = 0;
		u8 *imraw;

# ifndef OMITMASK
		imraw = (u8 *)&VEC_BUF(ifilters,i).m;
# else
		imraw = (u8 *)&ifiltermask;
# endif
		while (len < sizeof(IFT) && imraw[len] != 0x00) ++len;
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
	union {
		u32 v;
		size_t align;
	} numrestart;
} ;
VEC_STRUCT(statsvec,struct statstruct);

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

// 0123 4567 xxxx --3--> 3456 7xxx
// 0123 4567 xxxx --1--> 1234 567x
static inline void shiftpk(u8 *dst,const u8 *src,size_t sbits)
{
	size_t i,sbytes = sbits / 8;
	sbits %= 8;
	for (i = 0;i + sbytes < PUBLIC_LEN;++i) {
		dst[i] = (src[i+sbytes] << sbits) |
			(src[i+sbytes+1] >> (8 - sbits));
	}
	for(;i < PUBLIC_LEN;++i)
		dst[i] = 0;
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
	u8 wpk[PUBLIC_LEN + 1];
	size_t i;
	char *sname;
#ifdef STATISTICS
	struct statstruct *st = (struct statstruct *)task;
#endif

	memcpy(secret,skprefix,skprefixlen);
	memset(&pubonion,0,sizeof(pubonion));
	memcpy(pubonion.raw,pkprefix,pkprefixlen);
	// write version later as it will be overwritten by hash
	memcpy(hashsrc,checksumstr,checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = malloc(workdirlen + ONIONLEN + 63 + 1);
	if (!sname)
		abort();
	if (workdir)
		memcpy(sname,workdir,workdirlen);

initseed:
	randombytes(seed,sizeof(seed));
#ifdef STATISTICS
	++st->numrestart.v;
#endif

again:
	if (unlikely(endwork))
		goto end;

	ed25519_seckey_expand(sk,seed);
	ed25519_pubkey(pk,sk);

#ifdef STATISTICS
	++st->numcalc.v;
#endif

	DOFILTER(i,pk,{
		if (numwords > 1) {
			shiftpk(wpk,pk,filter_len(i));
			size_t j;
			for (int w = 1;;) {
				DOFILTER(j,wpk,goto secondfind);
				goto again;
			secondfind:
				if (++w >= numwords)
					break;
				shiftpk(wpk,wpk,filter_len(j));
			}
		}

		ADDNUMSUCCESS;

		// calc checksum
		memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
		FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
		// version byte
		pk[PUBLIC_LEN + 2] = 0x03;
		// base32
		strcpy(base32_to(&sname[direndpos],pk,PUBONION_LEN), ".onion");
		onionready(sname, secret, pubonion.raw);
		pubonion.i.hash[0] = 0;
		goto initseed;
	});
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
	u8 wpk[PUBLIC_LEN + 1];
	ge_p3 ge_public;
	size_t counter;
	size_t i;
	char *sname;
#ifdef STATISTICS
	struct statstruct *st = (struct statstruct *)task;
#endif

	memcpy(secret, skprefix, skprefixlen);
	memset(&pubonion,0,sizeof(pubonion));
	memcpy(pubonion.raw, pkprefix, pkprefixlen);
	// write version later as it will be overwritten by hash
	memcpy(hashsrc, checksumstr, checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = malloc(workdirlen + ONIONLEN + 63 + 1);
	if (!sname)
		abort();
	if (workdir)
		memcpy(sname, workdir, workdirlen);

initseed:
#ifdef STATISTICS
	++st->numrestart.v;
#endif
	randombytes(seed,sizeof(seed));
	ed25519_seckey_expand(sk,seed);
	
	ge_scalarmult_base(&ge_public,sk);
	ge_p3_tobytes(pk,&ge_public);
	
	for (counter = 0;counter < SIZE_MAX-8;counter += 8) {
		ge_p1p1 sum;
		
		if (unlikely(endwork))
			goto end;

		DOFILTER(i,pk,{
			if (numwords > 1) {
				//printf("numwords=%d,filter_len=%d\n",numwords,(int)filter_len(i));
				shiftpk(wpk,pk,filter_len(i));
				size_t j;
				for (int w = 1;;) {
					DOFILTER(j,wpk,goto secondfind);
					goto again;
				secondfind:
					if (++w >= numwords)
						break;
					shiftpk(wpk,wpk,filter_len(j));
				}
			}
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
			else
				goto initseed;

			ADDNUMSUCCESS;

			// calc checksum
			memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
			FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
			// version byte
			pk[PUBLIC_LEN + 2] = 0x03;
			// full name
			strcpy(base32_to(&sname[direndpos],pk,PUBONION_LEN),".onion");
			onionready(sname,secret,pubonion.raw);
			pubonion.i.hash[0] = 0;
			// don't reuse same seed
			goto initseed;
		});
	again:
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
		"\t-N numwords  - specify number of words per key (default - 1)\n"
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
	if (!s)
		abort();
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
			else if (*arg == 'N') {
				if (argc--)
					numwords = atoi(*argv++);
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

	filters_prepare();

	filters_print();

#ifdef STATISTICS
	if (!filters_count() && !reportdelay)
#else
	if (!filters_count())
#endif
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
	VEC_ADDN(threads,numthreads);
#ifdef STATISTICS
	VEC_INIT(stats);
	VEC_ADDN(stats,numthreads);
	VEC_ZERO(stats);
	VEC_INIT(tstats);
	VEC_ADDN(tstats,numthreads);
	VEC_ZERO(tstats);
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
		u64 sumcalc = 0,sumsuccess = 0,sumrestart = 0;
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
			// numrestart
			newt = VEC_BUF(stats,i).numrestart.v;
			tdiff = newt - VEC_BUF(tstats,i).oldnumrestart;
			VEC_BUF(tstats,i).oldnumrestart = newt;
			VEC_BUF(tstats,i).numrestart += (u64)tdiff;
			sumrestart += VEC_BUF(tstats,i).numrestart;
		}
		if (reportdelay && (!ireporttime || inowtime - ireporttime >= reportdelay)) {
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
				for (size_t i = 0;i < numthreads;++i) {
					VEC_BUF(tstats,i).numcalc = 0;
					VEC_BUF(tstats,i).numsuccess = 0;
					VEC_BUF(tstats,i).numrestart = 0;
				}
				elapsedoffset += inowtime - istarttime;
				istarttime = inowtime;
			}
		}
		if (sumcalc > U64_MAX / 2) {
			for (size_t i = 0;i < numthreads;++i) {
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
