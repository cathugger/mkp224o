#define VEC_STRUCT(typename,inttype) \
struct typename { \
	inttype *buf; \
	size_t len, alen; \
}
VEC_STRUCT(vec_basestruct,void) ;

#define VEC_INIT(ctl) memset(&ctl,0,sizeof(ctl))

void vec_add1(struct vec_basestruct *ctl,size_t sz);
#define VEC_ADD1(ctl) \
	vec_add1((struct vec_basestruct *)&(ctl),sizeof(*(ctl).buf))
#define VEC_ADD(ctl,val) { \
	VEC_ADD1(ctl); \
	(ctl).buf[(ctl).len - 1] = (val); \
}

void vec_addn(struct vec_basestruct *ctl,size_t sz,size_t n);
#define VEC_ADDN(ctl,n) \
	vec_addn((struct vec_basestruct *)&(ctl),sizeof(*(ctl).buf),(n))

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

#define VEC_ZERO(ctl) { \
	if ((ctl).buf) \
		memset((ctl).buf,0,(ctl).len * sizeof(*(ctl).buf)); \
}

#define VEC_FREE(ctl) { \
	free((ctl).buf); \
	memset(&(ctl), 0, sizeof((ctl))); \
}

#define VEC_LENGTH(ctl) ((ctl).len)
#define VEC_BUF(ctl,num) ((ctl).buf[num])

#define VEC_FOR(ctl,it) for (size_t it = 0;it < VEC_LENGTH((ctl));++it)
