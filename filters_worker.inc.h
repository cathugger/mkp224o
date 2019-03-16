
#ifdef BINFILTER

struct bfiltervec filters;

#endif // BINFILTER



#ifdef INTFILTER

struct ifiltervec filters;

# ifdef OMITMASK
IFT ifiltermask;
# endif

#endif // INTFILTER



#ifdef PCRE2FILTER

struct pfiltervec filters;

#endif // PCRE2FILTER



void filters_init(void)
{
	VEC_INIT(filters);
}



#include "filters_common.inc.h"



#ifdef INTFILTER

# ifndef BINSEARCH

#define MATCHFILTER(it,pk) \
	((*(IFT *)(pk) & VEC_BUF(filters,it).m) == VEC_BUF(filters,it).f)

#define DOFILTER(it,pk,code) \
do { \
	for (it = 0;it < VEC_LENGTH(filters);++it) { \
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
	for (size_t down = 0,up = VEC_LENGTH(filters);down < up;) { \
		it = (up + down) / 2; \
		if (maskedpk < VEC_BUF(filters,it).f) \
			up = it; \
		else if (maskedpk > VEC_BUF(filters,it).f) \
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
	for (size_t down = 0,up = VEC_LENGTH(filters);down < up;) { \
		it = (up + down) / 2; \
		IFT maskedpk = *(IFT *)(pk) & VEC_BUF(filters,it).m; \
		register int cmp = memcmp(&maskedpk,&VEC_BUF(filters,it).f,sizeof(IFT)); \
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

#define PREFILTER
#define POSTFILTER

#endif // INTFILTER


#ifdef BINFILTER

# ifndef BINSEARCH

#define MATCHFILTER(it,pk) ( \
	memcmp(pk,VEC_BUF(filters,it).f,VEC_BUF(filters,it).len) == 0 && \
	(pk[VEC_BUF(filters,it).len] & VEC_BUF(filters,it).mask) == VEC_BUF(filters,it).f[VEC_BUF(filters,it).len])

#define DOFILTER(it,pk,code) \
do { \
	for (it = 0;it < VEC_LENGTH(filters);++it) { \
		if (unlikely(MATCHFILTER(it,pk))) { \
			code; \
			break; \
		} \
	} \
} while (0)

# else // BINSEARCH

#define DOFILTER(it,pk,code) \
do { \
	for (size_t down = 0,up = VEC_LENGTH(filters);down < up;) { \
		it = (up + down) / 2; \
		{ \
			register int filterdiff = memcmp(pk,VEC_BUF(filters,it).f,VEC_BUF(filters,it).len); \
			if (filterdiff < 0) { \
				up = it; \
				continue; \
			} \
			if (filterdiff > 0) { \
				down = it + 1; \
				continue; \
			} \
		} \
		if ((pk[VEC_BUF(filters,it).len] & VEC_BUF(filters,it).mask) < \
			VEC_BUF(filters,it).f[VEC_BUF(filters,it).len]) \
		{ \
			up = it; \
			continue; \
		} \
		if ((pk[VEC_BUF(filters,it).len] & VEC_BUF(filters,it).mask) > \
			VEC_BUF(filters,it).f[VEC_BUF(filters,it).len]) \
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

#define PREFILTER
#define POSTFILTER

#endif // BINFILTER


#ifdef PCRE2FILTER

#define PREFILTER \
	char pkconvbuf[BASE32_TO_LEN(PUBLIC_LEN) + 1]; \
	pcre2_match_data *pcre2md = pcre2_match_data_create(128,0); \
	PCRE2_SIZE *pcre2ovector = 0;

#define POSTFILTER \
	pcre2_match_data_free(pcre2md);

#define DOFILTER(it,pk,code) \
do { \
	base32_to(pkconvbuf,pk,PUBLIC_LEN); \
	size_t __l = VEC_LENGTH(filters); \
	for (it = 0;it < __l;++it) { \
		int rc = pcre2_match(VEC_BUF(filters,it).re,(PCRE2_SPTR8)pkconvbuf,BASE32_TO_LEN(PUBLIC_LEN),0, \
			PCRE2_NO_UTF_CHECK,pcre2md,0); \
		if (unlikely(rc >= 0)) { \
			pcre2ovector = pcre2_get_ovector_pointer(pcre2md); \
			code; \
			break; \
		} \
	} \
} while (0)

#endif // PCRE2FILTER
