#ifdef __linux__
#define _POSIX_C_SOURCE 200112L
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include "types.h"
#include "likely.h"
#include "vec.h"
#include "base32.h"
#include "base64.h"
#include "cpucount.h"
#include "keccak.h"
#include "ed25519/ed25519.h"
#include "ioutil.h"
#include "constants.h"

#ifndef _WIN32
#define FSZ "%zu"
#else
#define FSZ "%Iu"
#endif

// additional 0 terminator is added by C
static const char pkprefix[] = "== ed25519v1-public: type0 ==\0\0";
#define pkprefixlen (sizeof(pkprefix)) // three null-terminators included
static const char skprefix[] = "== ed25519v1-secret: type0 ==\0\0";
#define skprefixlen (sizeof(skprefix)) // three null-terminators included
static const char checksumstr[] = ".onion checksum";
#define checksumstrlen (sizeof(checksumstr) - NULLTERM_LEN)

// output directory
static char *workdir = 0;
static size_t workdirlen = 0;

static int quietflag = 0;
//static int wantdedup = 0;
#define wantdedup 0

#define SECRET_LEN 64
#define PUBLIC_LEN 32
#define SEED_LEN   32
// with checksum + version num
#define PUBONION_LEN (PUBLIC_LEN + 3)
// with newline included
#define ONION_LEN 62

#define FORMATTED_SECRET_LEN (skprefixlen + SECRET_LEN)
#define FORMATTED_PUBLIC_LEN (pkprefixlen + PUBLIC_LEN)

static size_t onionendpos;   // end of .onion within string
static size_t direndpos;     // end of dir before .onion within string
static size_t printstartpos; // where to start printing from
static size_t printlen;      // precalculated, related to printstartpos

static pthread_mutex_t fout_mutex;
static FILE *fout;
static int yamloutput = 0;
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

#include "filters.h"

#ifdef STATISTICS
#define ADDNUMSUCCESS ++st->numsuccess.v
#else
#define ADDNUMSUCCESS do ; while (0)
#endif

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

typedef union {
	u8 raw[pkprefixlen + PUBLIC_LEN + 32];
	struct {
		u64 prefix[4];
		u64 key[4];
		u64 hash[4];
	} i;
} pubonionunion;



#define BUF_APPEND(buf,offset,src,srclen) strncpy(&buf[offset],src,srclen); offset += srclen;
#define BUF_APPEND_CSTR(buf,offset,src) BUF_APPEND(buf,offset,src,strlen(src))
#define BUF_APPEND_CHAR(buf,offet,c) buf[offset++] = c;

static void writekeys(const char *hostname, const u8 *formated_secret, const u8 *formated_public)
{
	char keysbuf[KEYS_LEN];
	size_t offset = 0;

	BUF_APPEND_CSTR(keysbuf, offset, keys_field_generated);
	BUF_APPEND_CHAR(keysbuf, offset, '\n');

	BUF_APPEND_CSTR(keysbuf, offset, keys_field_hostname);
	BUF_APPEND(keysbuf, offset, hostname, ONION_LEN);
	BUF_APPEND_CHAR(keysbuf, offset, '\n');

	BUF_APPEND_CSTR(keysbuf, offset, keys_field_secretkey);
	char seckeybuf[SECKEY_LEN + NULLTERM_LEN];
	base64_to(seckeybuf, formated_secret, FORMATTED_SECRET_LEN);
	BUF_APPEND(keysbuf, offset, seckeybuf, SECKEY_LEN);
	BUF_APPEND_CHAR(keysbuf, offset, '\n');

	BUF_APPEND_CSTR(keysbuf, offset, keys_field_publickey);
	char pubkeybuf[PUBKEY_LEN + NULLTERM_LEN];
	base64_to(pubkeybuf, formated_public, FORMATTED_PUBLIC_LEN);
	BUF_APPEND(keysbuf, offset, pubkeybuf, PUBKEY_LEN);
	BUF_APPEND_CHAR(keysbuf, offset, '\n');

	BUF_APPEND_CSTR(keysbuf, offset, keys_field_time);
	char timebuf[TIME_LEN + NULLTERM_LEN];
	time_t timer;
	struct tm* tm_info;
	time(&timer);
	tm_info = localtime(&timer);
	strftime(timebuf, TIME_LEN + NULLTERM_LEN, "%Y-%m-%d %H:%M:%S", tm_info);
	BUF_APPEND(keysbuf, offset, timebuf, TIME_LEN);
	BUF_APPEND_CHAR(keysbuf, offset, '\n');

	BUF_APPEND_CHAR(keysbuf, offset, '\n');

	assert(offset == KEYS_LEN);

	pthread_mutex_lock(&fout_mutex);
	fwrite(keysbuf,sizeof(keysbuf),1,fout);
	fflush(fout);
	pthread_mutex_unlock(&fout_mutex);
}

#undef BUF_APPEND_CHAR
#undef BUF_APPEND_CSTR
#undef BUF_APPEND

static void printhostname(const char *hostname)
{
	char buf[ONION_LEN + LINEFEED_LEN];
	strncpy(buf,hostname,ONION_LEN);
	buf[ONION_LEN] = '\n';

	pthread_mutex_lock(&fout_mutex);
	fwrite(buf,sizeof(buf),1,fout);
	fflush(fout);
	pthread_mutex_unlock(&fout_mutex);
}

static void onionready(char *sname,const u8 *secret,const u8 *pubonion)
{
	if (endwork)
		return;

	if (numneedgenerate) {
		pthread_mutex_lock(&keysgenerated_mutex);
		if (keysgenerated >= numneedgenerate) {
			pthread_mutex_unlock(&keysgenerated_mutex);
			return;
		}
	}

	if (numneedgenerate) {
		++keysgenerated;
		if (keysgenerated >= numneedgenerate)
			endwork = 1;
		pthread_mutex_unlock(&keysgenerated_mutex);
	}

	if (fout) {
		if (yamloutput) {
			writekeys(&sname[printstartpos],secret,pubonion);
			return;
		} else {
			printhostname(&sname[printstartpos]);
		}
	}

	if (createdir(sname,1) != 0) {
		if (numneedgenerate)
			pthread_mutex_unlock(&keysgenerated_mutex);
		return;
	}

	strcpy(&sname[onionendpos],"/hs_ed25519_secret_key");
	writetofile(sname,secret,skprefixlen + SECRET_LEN,1);

	strcpy(&sname[onionendpos],"/hostname");
	FILE *hfile = fopen(sname,"w");
	if (hfile) {
		sname[onionendpos] = '\n';
		fwrite(&sname[direndpos],ONION_LEN + 1,1,hfile);
		fclose(hfile);
	}

	strcpy(&sname[onionendpos],"/hs_ed25519_public_key");
	writetofile(sname,pubonion,pkprefixlen + PUBLIC_LEN,0);

}

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

static void *dowork(void *task)
{
	pubonionunion pubonion;
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
	PREFILTER

	memcpy(secret,skprefix,skprefixlen);
	wpk[PUBLIC_LEN] = 0;
	memset(&pubonion,0,sizeof(pubonion));
	memcpy(pubonion.raw,pkprefix,pkprefixlen);
	// write version later as it will be overwritten by hash
	memcpy(hashsrc,checksumstr,checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = (char *) malloc(workdirlen + ONION_LEN + 63 + 1);
	if (!sname)
		abort();
	if (workdir)
		memcpy(sname,workdir,workdirlen);

initseed:
	randombytes(seed,sizeof(seed));
	ed25519_seckey_expand(sk,seed);
#ifdef STATISTICS
	++st->numrestart.v;
#endif

again:
	if (unlikely(endwork))
		goto end;

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
				goto next;
			secondfind:
				if (++w >= numwords)
					break;
				shiftpk(wpk,wpk,filter_len(j));
			}
		}
		// sanity check
		if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
			goto initseed;

		ADDNUMSUCCESS;

		// calc checksum
		memcpy(&hashsrc[checksumstrlen],pk,PUBLIC_LEN);
		FIPS202_SHA3_256(hashsrc,sizeof(hashsrc),&pk[PUBLIC_LEN]);
		// version byte
		pk[PUBLIC_LEN + 2] = 0x03;
		// base32
		strcpy(base32_to(&sname[direndpos],pk,PUBONION_LEN),".onion");
		onionready(sname,secret,pubonion.raw);
		pk[PUBLIC_LEN] = 0;
		goto initseed;
	});
next:
	addsk32(sk);
	goto again;

end:
	free(sname);
	POSTFILTER
	sodium_memzero(secret,sizeof(secret));
	sodium_memzero(seed,sizeof(seed));
	return 0;
}

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

static void *dofastwork(void *task)
{
	pubonionunion pubonion;
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
	PREFILTER

	memcpy(secret,skprefix,skprefixlen);
	wpk[PUBLIC_LEN] = 0;
	memset(&pubonion,0,sizeof(pubonion));
	memcpy(pubonion.raw,pkprefix,pkprefixlen);
	// write version later as it will be overwritten by hash
	memcpy(hashsrc,checksumstr,checksumstrlen);
	hashsrc[checksumstrlen + PUBLIC_LEN] = 0x03; // version

	sname = (char *) malloc(workdirlen + ONION_LEN + 63 + 1);
	if (!sname)
		abort();
	if (workdir)
		memcpy(sname,workdir,workdirlen);

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
				shiftpk(wpk,pk,filter_len(i));
				size_t j;
				for (int w = 1;;) {
					DOFILTER(j,wpk,goto secondfind);
					goto next;
				secondfind:
					if (++w >= numwords)
						break;
					shiftpk(wpk,wpk,filter_len(j));
				}
			}
			// found!
			// update secret key with counter
			addsztoscalar32(sk,counter);
			// sanity check
			if ((sk[0] & 248) != sk[0] || ((sk[31] & 63) | 64) != sk[31])
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
			pk[PUBLIC_LEN] = 0;
			// don't reuse same seed
			goto initseed;
		});
	next:
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
	POSTFILTER
	sodium_memzero(secret,sizeof(secret));
	sodium_memzero(seed,sizeof(seed));
	return 0;
}

static void printhelp(FILE *out,const char *progname)
{
	fprintf(out,
		"Usage: %s filter [filter...] [options]\n"
		"       %s -f filterfile [options]\n"
		"Options:\n"
		"\t-h  - print help to stdout and quit\n"
		"\t-f  - instead of specifying filter(s) via commandline, specify filter file which contains filters separated by newlines\n"
		"\t-q  - do not print diagnostic output to stderr\n"
		"\t-x  - do not print onion names\n"
		"\t-o filename  - output onion names to specified file (append)\n"
		"\t-O filename  - output onion names to specified file (overwrite)\n"
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
		"\t-y  - output generated keys in yaml format instead of dumping them to filesystem\n"
		"\t-Y filename host.onion  - parse yaml encoded key file and extract key(s) to filesystem\n"
		,progname,progname);
	fflush(out);
}

enum {
	Q_ADDITIONAL = 101,
	Q_UNRECOGNISED,
	Q_NOSTATISTICS,
	Q_FAILOPENOUTPUT,
	Q_FAILTHREAD,
	Q_FAILTIME,
} ;

static void e_additional()
{
	fprintf(stderr,"additional argument required\n");
	exit(Q_ADDITIONAL);
}

#ifndef STATISTICS
static void e_nostatistics()
{
	fprintf(stderr,"statistics support not compiled in\n");
	exit(Q_NOSTATISTICS);
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

VEC_STRUCT(threadvec, pthread_t);


int parseandcreate(const char *filepath, const char *hostname)
{
	if (strlen(hostname) != ONION_LEN) {
		fprintf(stderr, "Invalid onion address \"%s\".\n", hostname);
		return 1;
	}

	char buf[16*1024];
	memset(buf, 0, sizeof(buf));
	FILE *fkeys = fopen(filepath, "r");
	if (fkeys == NULL) {
		fprintf(stderr, "Cannot open file with keys \"%s\" for reading.\n", filepath);
		return 2;
	}
	int error_number = 1;
	size_t readbytes = 0;
	while (1) {
		const size_t currentread = fread(
			buf + readbytes,  // Possibly we already partially receive desired onion address
			sizeof(buf[0]),
			sizeof(buf) - readbytes - NULLTERM_LEN,
			fkeys);
		if (currentread == 0) {
			fprintf(stderr, "Not found desired hostname \"%s\" in file \"%s\".\n", hostname, filepath);
			error_number = 3;
			break;
		}
		readbytes += currentread;
		buf[readbytes] = '\0';
		char *pfound = strstr(buf, hostname);
		if (pfound == NULL) {
			if (readbytes > ONION_LEN) {
				memmove(buf, buf + readbytes - ONION_LEN, ONION_LEN);
				readbytes = ONION_LEN;
			}
		} else {  // Got it!
			memmove(buf, pfound, readbytes - (pfound - buf));
			readbytes -= pfound - buf;
			buf[readbytes] = '\0';
			char *pendrecord = NULL;
			while (1) {
				const size_t currentread = fread(
					buf + readbytes,
					sizeof(buf[0]),
					sizeof(buf) - readbytes - NULLTERM_LEN,
					fkeys);
				readbytes += currentread;
				buf[readbytes] = '\0';
				pendrecord = strstr(buf, "\n\n");
				if (pendrecord != NULL || currentread == 0) {
					break;
				}
			}
			if (pendrecord == NULL) {
				fprintf(stderr, "Looks like file with keys \"%s\" is incomplete, found hostname but not keys.\n", filepath);
				error_number = 4;
				break;
			}

			const char *const pfield_sec_begin = strstr(buf, keys_field_secretkey);
			if (pfield_sec_begin == NULL) {
				fprintf(stderr, "Cannot find field with secret key within generated section.\n");
				error_number = 5;
				break;
			}
			const char *const p_sec_begin = pfield_sec_begin + KEYS_FIELD_SECRETKEY_LEN;
			if (pendrecord - p_sec_begin < BASE64_TO_LEN(FORMATTED_SECRET_LEN)) {
				fprintf(stderr, "Generated section it too small to keep base64 encoding of secret key.\n");
				error_number = 6;
				break;
			}
			char secbuf[FORMATTED_SECRET_LEN];
			if (-1 == base64_from((u8*)secbuf, p_sec_begin, BASE64_TO_LEN(FORMATTED_SECRET_LEN))) {
				fprintf(stderr, "Invalid base64 encoding of secret key.\n");
				error_number = 7;
				break;
			}

			const char *const pfield_pub_begin = strstr(buf, keys_field_publickey);
			if (pfield_pub_begin == NULL) {
				fprintf(stderr, "Cannot find field with public key within generated section.\n");
				error_number = 8;
				break;
			}
			const char *const p_pub_begin = pfield_pub_begin + KEYS_FIELD_PUBLICKEY_LEN;
			if (pendrecord - p_pub_begin < BASE64_TO_LEN(KEYS_FIELD_PUBLICKEY_LEN)) {
				fprintf(stderr, "Generated section it too small to keep base64 encoding of public key.\n");
				error_number = 9;
				break;
			}
			char pubbuf[FORMATTED_PUBLIC_LEN];
			if (-1 == base64_from((u8*)pubbuf, p_pub_begin, BASE64_TO_LEN(FORMATTED_PUBLIC_LEN))) {
				fprintf(stderr, "Invalid base64 encoding of secret key.\n");
				error_number = 10;
				break;
			}

			char pathbuf[1024];
			const size_t keys_directory_path_len = workdirlen + strlen(hostname);
			if (keys_directory_path_len >= sizeof(pathbuf)) {
				fprintf(stderr, "Keys directory path to is too long: %ld, max allowed length is %ld.\n", keys_directory_path_len, sizeof(pathbuf));
				error_number = 11;
				break;
			}
			strncpy(pathbuf, workdir, workdirlen);
			strncpy(pathbuf + workdirlen, hostname, strlen(hostname));
			pathbuf[keys_directory_path_len] = '\0';
			if (-1 == createdir(pathbuf, use_secret_mode)) {
				fprintf(stderr, "Cannot create directory \"%s\" for key files.\n", pathbuf);
				error_number = 12;
				break;
			}

			const size_t secretkey_filepath_len = keys_directory_path_len + PATH_SEPARATOR_LEN + strlen(secret_key_filename);
			if (secretkey_filepath_len >= sizeof(pathbuf)) {
				fprintf(stderr, "Path to file with secret key is too long %ld, max allowed length is %ld.\n", secretkey_filepath_len, sizeof(pathbuf));
				error_number = 13;
				break;
			}
			pathbuf[keys_directory_path_len] = '/';
			strncpy(pathbuf + keys_directory_path_len + PATH_SEPARATOR_LEN, secret_key_filename, strlen(secret_key_filename));
			pathbuf[secretkey_filepath_len] = '\0';
			if (-1 == writetofile(pathbuf, (u8*)secbuf, sizeof(secbuf), use_secret_mode)) {
				fprintf(stderr, "Can't write secret key to file \"%s\".\n", pathbuf);
				error_number = 14;
				break;
			}

			const size_t publickey_filepath_len = keys_directory_path_len + PATH_SEPARATOR_LEN + strlen(public_key_filename);
			if (publickey_filepath_len >= sizeof(pathbuf)) {
				fprintf(stderr, "Path to file with public key is too long %ld, max allowed length is %ld.\n", publickey_filepath_len, sizeof(pathbuf));
				error_number = 15;
				break;
			}
			pathbuf[keys_directory_path_len] = '/';
			strncpy(pathbuf + keys_directory_path_len + PATH_SEPARATOR_LEN, public_key_filename, strlen(public_key_filename));
			pathbuf[publickey_filepath_len] = '\0';
			if (-1 == writetofile(pathbuf, (u8*)pubbuf, sizeof(pubbuf), use_public_mode)) {
				fprintf(stderr, "Can't write public key to file \"%s\".\n", pathbuf);
				error_number = 16;
				break;
			}

			pathbuf[keys_directory_path_len] = '\0';
			fprintf(stderr, "Keys successfully exported to directory \"%s\".\n", pathbuf);
			error_number = 0;
			break;
		}
	}

	if (ferror(fkeys) || error_number) {
		fprintf(stderr, "Error #%d while parsing generated file \"%s\" or extracting keys.\n", error_number, filepath);
	}
	fclose(fkeys);
	return error_number;
}

int main(int argc,char **argv)
{
	const char *outfile = 0;
	const char *arg;
	int ignoreargs = 0;
	int dirnameflag = 0;
	int numthreads = 0;
	int fastkeygen = 1;
	int outfileoverwrite;
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

	setvbuf(stderr,0,_IONBF,0);
	fout = stdout;
	pthread_mutex_init(&keysgenerated_mutex,0);
	pthread_mutex_init(&fout_mutex,0);

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
					exit(Q_UNRECOGNISED);
				}
				++arg;
				if (!*arg)
					ignoreargs = 1;
				else if (!strcmp(arg,"help") || !strcmp(arg,"usage")) {
					printhelp(stdout,progname);
					exit(0);
				}
				else {
					fprintf(stderr,"unrecognised argument: --%s\n",arg);
					exit(Q_UNRECOGNISED);
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
			else if (*arg == 'f') {
				if (argc--)
					loadfilterfile(*argv++);
				else
					e_additional();
			}
			else if (*arg == 'q')
				++quietflag;
			else if (*arg == 'x')
				fout = 0;
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
				fastkeygen = 0;
			else if (*arg == 'z')
				fastkeygen = 1;
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
				const char *filepath = 0, *hostname = 0;
				if (argc--) {
					filepath = *argv++;
					if (argc--) {
						hostname = *argv++;
						return parseandcreate(filepath, hostname);
					}
					else
						e_additional();
				}
				else
					e_additional();
			}
			else {
				fprintf(stderr,"unrecognised argument: -%c\n",*arg);
				exit(Q_UNRECOGNISED);
			}
			if (numargit)
				goto nextarg;
		}
		else
			filters_add(arg);
	}

	if (outfile) {
		fout = fopen(outfile,!outfileoverwrite ? "a" : "w");
		if (!fout) {
			perror("failed to open output file");
			exit(Q_FAILOPENOUTPUT);
		}
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

	if (workdir)
		createdir(workdir,1);

	direndpos = workdirlen;
	onionendpos = workdirlen + ONION_LEN;

	if (!dirnameflag) {
		printstartpos = direndpos;
		printlen = ONION_LEN + 1;
	} else {
		printstartpos = 0;
		printlen = onionendpos + 1;
	}

	if (numthreads <= 0) {
		numthreads = cpucount();
		if (numthreads <= 0)
			numthreads = 1;
		if (!quietflag)
			fprintf(stderr,"using %d %s\n",
				numthreads,numthreads == 1 ? "thread" : "threads");
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

	pthread_attr_t tattr,*tattrp = &tattr;
	tret = pthread_attr_init(tattrp);
	if (tret) {
		perror("pthread_attr_init");
		tattrp = 0;
	}
	else {
		tret = pthread_attr_setstacksize(tattrp,80<<10);
		if (tret)
			perror("pthread_attr_setstacksize");
	}

	for (size_t i = 0;i < VEC_LENGTH(threads);++i) {
		void *tp = 0;
#ifdef STATISTICS
		tp = &VEC_BUF(stats,i);
#endif
		tret = pthread_create(&VEC_BUF(threads,i),tattrp,fastkeygen ? dofastwork : dowork,tp);
		if (tret) {
			fprintf(stderr,"error while making " FSZ "th thread: %s\n",i,strerror(tret));
			exit(Q_FAILTHREAD);
		}
	}

	if (tattrp) {
		tret = pthread_attr_destroy(tattrp);
		if (tret)
			perror("pthread_attr_destroy");
	}

#ifdef STATISTICS
	struct timespec nowtime;
	u64 istarttime,inowtime,ireporttime = 0,elapsedoffset = 0;
	if (clock_gettime(CLOCK_MONOTONIC,&nowtime) < 0) {
		perror("failed to get time");
		exit(Q_FAILTIME);
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
	if (!quietflag)
		fprintf(stderr," done.\n");

	pthread_mutex_destroy(&keysgenerated_mutex);
	pthread_mutex_destroy(&fout_mutex);
	filters_clean();

	if (outfile)
		fclose(fout);

	return 0;
}
