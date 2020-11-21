#ifdef INTFILTER

static inline size_t S(filter_len)(size_t i)
{
# ifndef OMITMASK
	const u8 *m = (const u8 *)&VEC_BUF(filters,i).m;
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
#define filter_len S(filter_len)

#endif // INTFILTER

#ifdef BINFILTER

static inline size_t S(filter_len)(size_t i)
{
	size_t c = VEC_BUF(filters,i).len * 8;
	u8 v = VEC_BUF(filters,i).mask;
	for (size_t k = 0;;) {
		if (!v)
			return c;
		++c;
		if (++k >= 8)
			return c;
		v <<= 1;
	}
}
#define filter_len S(filter_len)

#endif // BINFILTER

#ifdef PCRE2FILTER

#define filter_len(i) ((pcre2ovector[1] - pcre2ovector[0]) * 5)

#endif // PCRE2FILTER
