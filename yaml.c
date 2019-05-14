#define _POSIX_C_SOURCE 200112L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#ifndef _WIN32
#include <signal.h>
#endif

#include "types.h"
#include "yaml.h"
#include "ioutil.h"
#include "base32.h"
#include "base64.h"
#include "common.h"

#define LINEFEED_LEN       (sizeof(char))
#define NULLTERM_LEN       (sizeof(char))
#define PATH_SEPARATOR_LEN (sizeof(char))

static const char keys_field_generated[] = "---";
static const char keys_field_hostname[]  = "hostname: ";
static const char keys_field_publickey[] = "hs_ed25519_public_key: ";
static const char keys_field_secretkey[] = "hs_ed25519_secret_key: ";
static const char keys_field_time[]      = "time: ";

#define KEYS_FIELD_GENERATED_LEN (sizeof(keys_field_generated) - NULLTERM_LEN)
#define KEYS_FIELD_HOSTNAME_LEN  (sizeof(keys_field_hostname)  - NULLTERM_LEN)
#define KEYS_FIELD_PUBLICKEY_LEN (sizeof(keys_field_publickey) - NULLTERM_LEN)
#define KEYS_FIELD_SECRETKEY_LEN (sizeof(keys_field_secretkey) - NULLTERM_LEN)
#define KEYS_FIELD_TIME_LEN      (sizeof(keys_field_time)      - NULLTERM_LEN)

#define B64_PUBKEY_LEN (BASE64_TO_LEN(FORMATTED_PUBLIC_LEN))
#define B64_SECKEY_LEN (BASE64_TO_LEN(FORMATTED_SECRET_LEN))
#define TIME_LEN       (21 * sizeof(char)) // strlen("2018-07-04 21:31:20 Z")

#define KEYS_LEN ( \
	KEYS_FIELD_GENERATED_LEN + LINEFEED_LEN + \
	KEYS_FIELD_HOSTNAME_LEN + ONION_LEN + LINEFEED_LEN + \
	KEYS_FIELD_PUBLICKEY_LEN + B64_PUBKEY_LEN + LINEFEED_LEN + \
	KEYS_FIELD_SECRETKEY_LEN + B64_SECKEY_LEN + LINEFEED_LEN + \
	KEYS_FIELD_TIME_LEN + TIME_LEN + LINEFEED_LEN \
)

static pthread_mutex_t tminfo_mutex;

void yamlout_init(void)
{
	pthread_mutex_init(&tminfo_mutex,0);
}

void yamlout_clean(void)
{
	pthread_mutex_destroy(&tminfo_mutex);
}

#define BUF_APPEND(buf,offset,src,srclen) \
do { \
	memcpy(&buf[offset],(src),(srclen)); \
	offset += (srclen); \
} while (0)
#define BUF_APPEND_CSTR(buf,offset,src) BUF_APPEND(buf,offset,src,strlen(src))
#define BUF_APPEND_CHAR(buf,offset,c) buf[offset++] = (c)

void yamlout_writekeys(const char *hostname,const u8 *formated_public,const u8 *formated_secret)
{
	char keysbuf[KEYS_LEN];
	char pubkeybuf[B64_PUBKEY_LEN + NULLTERM_LEN];
	char seckeybuf[B64_SECKEY_LEN + NULLTERM_LEN];
	char timebuf[TIME_LEN + NULLTERM_LEN];
	size_t offset = 0;

	BUF_APPEND(keysbuf,offset,keys_field_generated,KEYS_FIELD_GENERATED_LEN);
	BUF_APPEND_CHAR(keysbuf,offset,'\n');

	BUF_APPEND(keysbuf,offset,keys_field_hostname,KEYS_FIELD_HOSTNAME_LEN);
	BUF_APPEND(keysbuf,offset,hostname,ONION_LEN);
	BUF_APPEND_CHAR(keysbuf,offset,'\n');

	BUF_APPEND(keysbuf,offset,keys_field_publickey,KEYS_FIELD_PUBLICKEY_LEN);
	base64_to(pubkeybuf,formated_public,FORMATTED_PUBLIC_LEN);
	BUF_APPEND(keysbuf,offset,pubkeybuf,B64_PUBKEY_LEN);
	BUF_APPEND_CHAR(keysbuf,offset,'\n');

	BUF_APPEND(keysbuf,offset,keys_field_secretkey,KEYS_FIELD_SECRETKEY_LEN);
	base64_to(seckeybuf,formated_secret,FORMATTED_SECRET_LEN);
	BUF_APPEND(keysbuf,offset,seckeybuf,B64_SECKEY_LEN);
	BUF_APPEND_CHAR(keysbuf,offset,'\n');

	BUF_APPEND(keysbuf,offset,keys_field_time,KEYS_FIELD_TIME_LEN);

	time_t currtime;
	time(&currtime);
	struct tm *tm_info;

	pthread_mutex_lock(&tminfo_mutex);
	tm_info = gmtime(&currtime);
	strftime(timebuf,sizeof(timebuf),"%Y-%m-%d %H:%M:%S Z",tm_info);
	pthread_mutex_unlock(&tminfo_mutex);

	BUF_APPEND(keysbuf,offset,timebuf,TIME_LEN);
	BUF_APPEND_CHAR(keysbuf,offset,'\n');

	assert(offset == KEYS_LEN);

	pthread_mutex_lock(&fout_mutex);
	fwrite(keysbuf,sizeof(keysbuf),1,fout);
	fflush(fout);
	pthread_mutex_unlock(&fout_mutex);
}

#undef BUF_APPEND_CHAR
#undef BUF_APPEND_CSTR
#undef BUF_APPEND

// pseudo YAML parser
int yamlin_parseandcreate(FILE *fin,char *sname,const char *hostname)
{
	char line[256];
	size_t len,cnt;
	u8 pubbuf[BASE64_DATA_ALIGN(FORMATTED_PUBLIC_LEN)];
	u8 secbuf[BASE64_DATA_ALIGN(FORMATTED_SECRET_LEN)];
	int hashost = 0,haspub = 0,hassec = 0,skipthis = 0;
	enum keytype { HOST, PUB, SEC } keyt;

	while (!feof(fin) && !ferror(fin)) {
		if (!fgets(line,sizeof(line),fin))
			break;

		len = strlen(line);

		// trim whitespace from the end
		while (len != 0 && (line[len-1] == ' ' || line[len-1] == '\n' || line[len-1] == '\r'))
			line[--len] = '\0';

		// skip empty lines
		if (len == 0)
			continue;

		if (len >= 3 && line[0] == '-' && line[1] == '-' && line[2] == '-') {
			// end of document indicator
			if (!skipthis && (hashost || haspub || hassec)) {
				fprintf(stderr,"ERROR: incomplete record\n");
				return 1;
			}
			hashost = haspub = hassec = skipthis = 0;
			continue;
		}

		if (skipthis)
			continue;

		char *start = line;
		// trim whitespace
		while (len != 0 && *start == ' ') {
			++start;
			--len;
		}
		// find ':'
		char *p = start;
		for (;*p != '\0';++p) {
			if (*p == ':') {
				*p++ = '\0';
				goto foundkey;
			}
		}
		// not `key: value`
		fprintf(stderr,"ERROR: invalid syntax\n");
		return 1; // XXX could continue too there but eh

	foundkey:

		if (!strcmp(start,"hostname"))
			keyt = HOST;
		else if (!strcmp(start,"hs_ed25519_public_key"))
			keyt = PUB;
		else if (!strcmp(start,"hs_ed25519_secret_key"))
			keyt = SEC;
		else
			continue; // uninterested

		// skip WS
		while (*p == ' ')
			++p;
		if (*p == '!') {
			// skip ! tag
			while (*p != '\0' && *p != ' ')
				++p;
			// skip WS
			while (*p == ' ')
				++p;
		}
		len = strlen(p);
		switch (keyt) {
			case HOST:
				if (len != ONION_LEN ||
					base32_valid(p,&cnt) ||
					cnt != BASE32_TO_LEN(PUBONION_LEN) ||
					strcmp(&p[cnt],".onion") != 0)
				{
					fprintf(stderr,"ERROR: invalid hostname syntax\n");
					return 1;
				}
				if (!hostname || !strcmp(hostname,p)) {
					memcpy(&sname[direndpos],p,len + 1);
					hashost = 1;
				} else
					skipthis = 1;
				break;
			case PUB:
				if (len != B64_PUBKEY_LEN || !base64_valid(p,0) ||
					base64_from(pubbuf,p,len) != FORMATTED_PUBLIC_LEN)
				{
					fprintf(stderr,"ERROR: invalid pubkey syntax\n");
					return 1;
				}
				haspub = 1;
				break;
			case SEC:
				if (len != B64_SECKEY_LEN || !base64_valid(p,0) ||
					base64_from(secbuf,p,len) != FORMATTED_SECRET_LEN)
				{
					fprintf(stderr,"ERROR: invalid seckey syntax\n");
					return 1;
				}
				hassec = 1;
				break;
		}
		if (hashost && haspub && hassec) {
#ifndef _WIN32
			sigset_t nset,oset;
			sigemptyset(&nset);
			sigaddset(&nset,SIGINT);
			sigaddset(&nset,SIGTERM);
			sigprocmask(SIG_BLOCK,&nset,&oset);
#endif
			if (createdir(sname,1) != 0) {
				fprintf(stderr,"ERROR: could not create directory for key output\n");
				return 1;
			}

			strcpy(&sname[onionendpos],"/hs_ed25519_secret_key");
			writetofile(sname,secbuf,FORMATTED_SECRET_LEN,1);

			strcpy(&sname[onionendpos],"/hs_ed25519_public_key");
			writetofile(sname,pubbuf,FORMATTED_PUBLIC_LEN,0);

			strcpy(&sname[onionendpos],"/hostname");
			FILE *hfile = fopen(sname,"w");
			sname[onionendpos] = '\n';
			if (hfile) {
				fwrite(&sname[direndpos],ONION_LEN + 1,1,hfile);
				fclose(hfile);
			}
			if (fout) {
				fwrite(&sname[printstartpos],printlen,1,fout);
				fflush(fout);
			}
#ifndef _WIN32
			sigprocmask(SIG_SETMASK,&oset,0);
#endif
			if (hostname)
				return 0; // finished
			skipthis = 1;
		}
	}

	if (!feof(fin)) {
		fprintf(stderr,"error while reading input\n");
		return 1;
	}

	if (hostname) {
		fprintf(stderr,"hostname wasn't found in input\n");
		return 1;
	}

	return 0;
}
