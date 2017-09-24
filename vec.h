#define VEC_STRUCT(typename, inttype) \
struct typename { \
	inttype *buf; \
	size_t len, alen; \
}

#define VEC_INIT(ctl) memset(&ctl, 0, sizeof(ctl))

#define VEC_ADD(ctl, val) { \
	if (!(ctl).alen) { \
		(ctl).alen = 8; \
		(ctl).buf = malloc(8 * sizeof(val)); \
	} else if ((ctl).len >= (ctl).alen) { \
		(ctl).alen *= 2; \
		(ctl).buf = realloc((ctl).buf, (ctl).alen * sizeof(val)); \
	} \
	(ctl).buf[(ctl).len++] = val; \
}

#define VEC_ADDN(ctl, valt, n) { \
	if (!(ctl).alen) { \
		(ctl).alen = 8; \
		(ctl).buf = malloc(8 * sizeof(valt)); \
	} \
	size_t nlen = (ctl).alen; \
	while ((ctl).len + n > nlen) \
		nlen *= 2; \
	if (nlen > (ctl).alen) { \
		(ctl).alen = nlen; \
		(ctl).buf = realloc((ctl).buf, nlen * sizeof(valt)); \
	} \
	(ctl).len += n; \
}

#define VEC_FREE(ctl) { free((ctl).buf); memset(&(ctl), 0, sizeof((ctl))); }

#define VEC_LENGTH(ctl) ((ctl).len)
#define VEC_BUF(ctl, num) ((ctl).buf[num])
