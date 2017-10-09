#define VEC_STRUCT(typename,inttype) \
struct typename { \
	inttype *buf; \
	size_t len, alen; \
}

#define VEC_INIT(ctl) memset(&ctl,0,sizeof(ctl))

#define VEC_ADD1(ctl) { \
	if (!(ctl).alen) { \
		(ctl).alen = 8; \
		(ctl).buf = malloc(8 * sizeof(*(ctl).buf)); \
	} else if ((ctl).len >= (ctl).alen) { \
		(ctl).alen *= 2; \
		(ctl).buf = realloc((ctl).buf,(ctl).alen * sizeof(*(ctl).buf)); \
	} \
	++(ctl).len; \
}

#define VEC_ADD(ctl,val) { \
	if (!(ctl).alen) { \
		(ctl).alen = 8; \
		(ctl).buf = malloc(8 * sizeof(*(ctl).buf)); \
	} else if ((ctl).len >= (ctl).alen) { \
		(ctl).alen *= 2; \
		(ctl).buf = realloc((ctl).buf,(ctl).alen * sizeof(*(ctl).buf)); \
	} \
	(ctl).buf[(ctl).len++] = (val); \
}

#define VEC_ADDN(ctl,n) { \
	if (!(ctl).alen) { \
		(ctl).alen = 8; \
		(ctl).buf = malloc(8 * sizeof(*(ctl).buf)); \
	} \
	size_t nlen = (ctl).alen; \
	while ((ctl).len + n > nlen) \
		nlen *= 2; \
	if (nlen > (ctl).alen) { \
		(ctl).alen = nlen; \
		(ctl).buf = realloc((ctl).buf,nlen * sizeof(*(ctl).buf)); \
	} \
	(ctl).len += n; \
}

#define VEC_REMOVE(ctl,n) { \
	--(ctl).len; \
	memmove( \
		&(ctl).buf[(n)], \
		&(ctl).buf[(n + 1)], \
		((ctl).len - (n)) * sizeof(*(ctl).buf)); \
}

#define VEC_INSERT1(ctl,n) { \
	VEC_ADD1(ctl); \
	memmove( \
		&(ctl).buf[(n + 1)], \
		&(ctl).buf[(n)], \
		((ctl).len - (n) - 1) * sizeof(*(ctl).buf)); \
}

#define VEC_INSERT(ctl,n,val) { \
	VEC_INSERT1(ctl,n); \
	(ctl).buf[n] = (val); \
}

#define VEC_INSERTN(ctl,n,m) { \
	VEC_ADDN(ctl,m); \
	memmove( \
		&(ctl).buf[(n + m)], \
		&(ctl).buf[(n)], \
		((ctl).len - (n) - (m)) * sizeof(*(ctl).buf)); \
}

#define VEC_ZERO(ctl) \
	memset((ctl).buf,0,(ctl).len * sizeof(*(ctl).buf))

#define VEC_FREE(ctl) { \
	free((ctl).buf); \
	memset(&(ctl), 0, sizeof((ctl))); \
}

#define VEC_LENGTH(ctl) ((ctl).len)
#define VEC_BUF(ctl,num) ((ctl).buf[num])

#define VEC_FOR(ctl,it) for (size_t it = 0;it < VEC_LENGTH((ctl));++it)
