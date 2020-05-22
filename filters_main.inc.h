
#include "filters_common.inc.h"

#ifdef INTFILTER

# ifdef OMITMASK

static inline int filter_compare(const void *p1,const void *p2)
{
	if (((const struct intfilter *)p1)->f < ((const struct intfilter *)p2)->f)
		return -1;
	if (((const struct intfilter *)p1)->f > ((const struct intfilter *)p2)->f)
		return 1;
	return 0;
}

#  ifdef EXPANDMASK

/*
 * for mask expansion, we need to figure out how much bits
 * we need to fill in with different values.
 * while in big endian machines this is quite easy,
 * representation we use for little endian ones may
 * leave gap of bits we don't want to touch.
 *
 * initial idea draft:
 *
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
 *
 * above method doesn't work in some cases. better way:
 *
 * l: 0x80ffFFff ^ 0x00f0FFff -> 0x800f0000
 *   0x800f0000 >> 16 -> 0x0000800f
 *   0x0000800f + 1 -> 0x00008010
 *   0x0000800f & 0x00008010 -> 0x00008000 <- smask
 *   0x0000800f ^ 0x00008000 -> 0x0000000f <- dmask
 *
 * cross <- difference between mask we desire and mask we currently have
 * shift cross to left variable ammount of times to eliminate zeros
 *   save shift ammount as ishift (initial shift)
 * then, we eliminate first area of ones; if there was no gap, result is already all zeros
 *   save this thing as smask. it's only higher bits.
 * XOR smask and cross; result is only lower bits.
 * shift smask to left variable ammount of times until gap is eliminated.
 *   save resulting mask as cmask;
 *   save resulting shift value as rshift.
 */

int flattened = 0;

#define EXPVAL(init,j,dmask,smask,ishift,rshift) \
	((init) | ((((j) & (dmask)) | (((j) << (rshift)) & (smask))) << (ishift)))
// add expanded set of values
// allocates space on its own
static void ifilter_addexpanded(
	struct intfilter *ifltr,
	IFT dmask,IFT smask,IFT cmask,
	int ishift,int rshift)
{
	flattened = 1;
	size_t i = VEC_LENGTH(filters);
	VEC_ADDN(filters,cmask + 1);
	for (size_t j = 0;;++j) {
		VEC_BUF(filters,i + j).f =
			EXPVAL(ifltr->f,j,dmask,smask,ishift,rshift);
		if (j == cmask)
			break;
	}
}

// expand existing stuff
// allocates needed stuff on its own
static void ifilter_expand(IFT dmask,IFT smask,IFT cmask,int ishift,int rshift)
{
	flattened = 1;
	size_t len = VEC_LENGTH(filters);
	VEC_ADDN(filters,cmask * len);
	size_t esz = cmask + 1; // size of expanded elements
	for (size_t i = len - 1;;--i) {
		for (IFT j = 0;;++j) {
			VEC_BUF(filters,i * esz + j).f =
				EXPVAL(VEC_BUF(filters,i).f,j,dmask,smask,ishift,rshift);
			if (j == cmask)
				break;
		}
		if (i == 0)
			break;
	}
}

static inline void ifilter_addflatten(struct intfilter *ifltr,IFT mask)
{
	if (VEC_LENGTH(filters) == 0) {
		// simple
		VEC_ADD(filters,*ifltr);
		ifiltermask = mask;
		return;
	}
	if (ifiltermask == mask) {
		// lucky
		VEC_ADD(filters,*ifltr);
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
		VEC_ADD(filters,*ifltr);
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
static inline int filter_compare(const void *p1,const void *p2)
{
	return memcmp(p1,p2,sizeof(struct intfilter));
}

# endif // OMITMASK

static void filter_sort(void)
{
	size_t len = VEC_LENGTH(filters);
	if (len > 0)
		qsort(&VEC_BUF(filters,0),len,sizeof(struct intfilter),&filter_compare);
}

#endif // INTFILTER

#ifdef BINFILTER

static inline int filter_compare(const void *p1,const void *p2)
{
	const struct binfilter *b1 = (const struct binfilter *)p1;
	const struct binfilter *b2 = (const struct binfilter *)p2;

	size_t l = b1->len <= b2->len ? b1->len : b2->len;

	int cmp = memcmp(b1->f,b2->f,l);
	if (cmp != 0)
		return cmp;

	if (b1->len < b2->len)
		return -1;
	if (b1->len > b2->len)
		return +1;

	u8 cmask = b1->mask & b2->mask;
	if ((b1->f[l] & cmask) < (b2->f[l] & cmask))
		return -1;
	if ((b1->f[l] & cmask) > (b2->f[l] & cmask))
		return +1;

	if (b1->mask < b2->mask)
		return -1;
	if (b1->mask > b2->mask)
		return +1;

	return 0;
}

static void filter_sort(void)
{
	size_t len = VEC_LENGTH(filters);
	if (len > 0)
		qsort(&VEC_BUF(filters,0),len,sizeof(struct binfilter),&filter_compare);
}

#endif // BINFILTER



#ifndef PCRE2FILTER
static inline int filters_a_includes_b(size_t a,size_t b)
{
# ifdef INTFILTER
#  ifdef OMITMASK
	return VEC_BUF(filters,a).f == VEC_BUF(filters,b).f;
#  else // OMITMASK
	return VEC_BUF(filters,a).f == (VEC_BUF(filters,b).f & VEC_BUF(filters,a).m);
#  endif // OMITMASK
# else // INTFILTER
	const struct binfilter *fa = &VEC_BUF(filters,a);
	const struct binfilter *fb = &VEC_BUF(filters,b);

	if (fa->len > fb->len)
		return 0;
	size_t l = fa->len;

	int cmp = memcmp(fa->f,fb->f,l);
	if (cmp != 0)
		return 0;

	if (fa->len < fb->len)
		return 1;

	if (fa->mask > fb->mask)
		return 0;

	return fa->f[l] == (fb->f[l] & fa->mask);
# endif // INTFILTER
}

static void filters_dedup(void)
{
	size_t last = ~(size_t)0; // index after last matching element
	size_t chk;               // element to compare against
	size_t st;                // start of area to destroy

	size_t len = VEC_LENGTH(filters);
	for (size_t i = 1;i < len;++i) {
		if (last != i) {
			if (filters_a_includes_b(i - 1,i)) {
				if (last != ~(size_t)0) {
					memmove(&VEC_BUF(filters,st),
						&VEC_BUF(filters,last),
						(i - last) * VEC_ELSIZE(filters));
					st += i - last;
				}
				else
					st = i;
				chk = i - 1;
				last = i + 1;
			}
		}
		else {
			if (filters_a_includes_b(chk,i))
				last = i + 1;
		}
	}
	if (last != ~(size_t)0) {
		memmove(&VEC_BUF(filters,st),
			&VEC_BUF(filters,last),
			(len - last) * VEC_ELSIZE(filters));
		st += len - last;
		VEC_SETLENGTH(filters,st);
	}
}
#endif // !PCRE2FILTER

static void filters_clean(void)
{
#ifdef PCRE2FILTER
	for (size_t i = 0;i < VEC_LENGTH(filters);++i) {
		pcre2_code_free(VEC_BUF(filters,i).re);
		free(VEC_BUF(filters,i).str);
	}
#endif
	VEC_FREE(filters);
}

size_t filters_count(void)
{
	return VEC_LENGTH(filters);
}


static void filters_print(void)
{
	if (quietflag)
		return;
	size_t i,l;
	l = VEC_LENGTH(filters);
	if (l)
		fprintf(stderr,"filters:\n");

	for (i = 0;i < l;++i) {
#ifdef NEEDBINFILTER
		char buf0[256],buf1[256];
		u8 bufx[128];
#endif

		if (!verboseflag && i >= 20) {
			size_t notshown = l - i;
			fprintf(stderr,"[another " FSZ " %s not shown]\n",
				notshown,notshown == 1 ? "filter" : "filters");
			break;
		}

#ifdef INTFILTER
		size_t len = 0;
		u8 *imraw;

# ifndef OMITMASK
		imraw = (u8 *)&VEC_BUF(filters,i).m;
# else
		imraw = (u8 *)&ifiltermask;
# endif
		while (len < sizeof(IFT) && imraw[len] != 0x00) ++len;
		u8 mask = imraw[len-1];
		u8 *ifraw = (u8 *)&VEC_BUF(filters,i).f;
#endif // INTFILTER

#ifdef BINFILTER
		size_t len = VEC_BUF(filters,i).len + 1;
		u8 mask = VEC_BUF(filters,i).mask;
		u8 *ifraw = VEC_BUF(filters,i).f;
#endif // BINFILTER
#ifdef NEEDBINFILTER
		base32_to(buf0,ifraw,len);
		memcpy(bufx,ifraw,len);
		bufx[len - 1] |= ~mask;
		base32_to(buf1,bufx,len);
		char *a = buf0,*b = buf1;
		while (*a && *a == *b)
			++a, ++b;
		*a = 0;
		fprintf(stderr,"\t%s\n",buf0);
#endif // NEEDBINFILTER
#ifdef PCRE2FILTER
		fprintf(stderr,"\t%s\n",VEC_BUF(filters,i).str);
#endif // PCRE2FILTER
	}
	fprintf(stderr,"in total, " FSZ " %s\n",l,l == 1 ? "filter" : "filters");
}

void filters_add(const char *filter)
{
#ifdef NEEDBINFILTER
	struct binfilter bf;
	size_t ret;
# ifdef INTFILTER
	union intconv {
		IFT i;
		u8 b[sizeof(IFT)];
	} fc,mc;
# endif

	// skip regex start symbol. we do not support regex tho
	if (*filter == '^')
		++filter;

	memset(&bf,0,sizeof(bf));

	if (!base32_valid(filter,&ret)) {
		fprintf(stderr,"filter \"%s\" is invalid\n",filter);
		fprintf(stderr,"        ");
		while (ret--)
			fputc(' ',stderr);
		fprintf(stderr,"^\n");
		return;
	}

	ret = BASE32_FROM_LEN(ret);
	if (!ret)
		return;
# ifdef INTFILTER
	size_t maxsz = sizeof(IFT);
# else
	size_t maxsz = sizeof(bf.f);
# endif
	if (ret > maxsz) {
		fprintf(stderr,"filter \"%s\" is too long\n",filter);
		fprintf(stderr,"        ");
		maxsz = (maxsz * 8) / 5;
		while (maxsz--)
			fputc(' ',stderr);
		fprintf(stderr,"^\n");
		return;
	}
	base32_from(bf.f,&bf.mask,filter);
	bf.len = ret - 1;

# ifdef INTFILTER
	mc.i = 0;
	for (size_t i = 0;i < bf.len;++i)
		mc.b[i] = 0xFF;
	mc.b[bf.len] = bf.mask;
	memcpy(fc.b,bf.f,sizeof(fc.b));
	fc.i &= mc.i;

	struct intfilter ifltr = {
		.f = fc.i,
#  ifndef OMITMASK
		.m = mc.i,
#  endif
	};

#  ifdef OMITMASK
	ifilter_addflatten(&ifltr,mc.i);
#  else // OMITMASK
	VEC_ADD(filters,ifltr);
#  endif // OMITMASK
# endif // INTFILTER

# ifdef BINFILTER
	VEC_ADD(filters,bf);
# endif // BINFILTER
#endif // NEEDBINFILTER

#ifdef PCRE2FILTER
	int errornum;
	PCRE2_SIZE erroroffset;
	pcre2_code *re;

	re = pcre2_compile((PCRE2_SPTR8)filter,PCRE2_ZERO_TERMINATED,
		PCRE2_NO_UTF_CHECK | PCRE2_ANCHORED,&errornum,&erroroffset,0);
	if (!re) {
		PCRE2_UCHAR buffer[1024];
		pcre2_get_error_message(errornum,buffer,sizeof(buffer));
		fprintf(stderr,"PCRE2 compilation failed at offset " FSZ ": %s\n",
			(size_t)erroroffset,buffer);
		return;
	}

	// attempt to JIT. ignore error
	(void) pcre2_jit_compile(re,PCRE2_JIT_COMPLETE);

	struct pcre2filter f;
	memset(&f,0,sizeof(f));
	f.re = re;
	size_t fl = strlen(filter) + 1;
	f.str = (char *) malloc(fl);
	if (!f.str)
		abort();
	memcpy(f.str,filter,fl);
	VEC_ADD(filters,f);
#endif // PCRE2FILTER
}

static void filters_prepare(void)
{
#ifndef PCRE2FILTER
	if (!quietflag)
		fprintf(stderr,"sorting filters...");
	filter_sort();
	if (wantdedup) {
		if (!quietflag)
			fprintf(stderr," removing duplicates...");
		filters_dedup();
	}
	if (!quietflag)
		fprintf(stderr," done.\n");
#endif
}

static bool loadfilterfile(const char *fname)
{
	char buf[128];
	FILE *f = fopen(fname,"r");
	if (!f)
		return false;
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
	return true;
}
