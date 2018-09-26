#define VEC_STRUCT(typename,inttype) \
struct typename { \
	inttype *buf; \
	size_t len,alen; \
}
VEC_STRUCT(vec_basestruct,void) ;

#define VEC_INIT(ctl) memset(&ctl,0,sizeof(ctl))

#define VEC_ELSIZE(ctl) (sizeof(*(ctl).buf))

void vec_add1(struct vec_basestruct *ctl,size_t sz);
#define VEC_ADD1(ctl) \
	vec_add1((struct vec_basestruct *)&(ctl),VEC_ELSIZE(ctl))
#define VEC_ADD(ctl,val) \
do { \
	VEC_ADD1(ctl); \
	(ctl).buf[(ctl).len - 1] = (val); \
} while (0)

void vec_addn(struct vec_basestruct *ctl,size_t sz,size_t n);
#define VEC_ADDN(ctl,n) \
	vec_addn((struct vec_basestruct *)&(ctl),VEC_ELSIZE(ctl),(size_t)(n))

#define VEC_SETLENGTH(ctl,n) \
do { \
	(ctl).len = n; \
} while (0)

#define VEC_REMOVEN(ctl,n,m) \
do { \
	(ctl).len -= m; \
	memmove( \
		&(ctl).buf[n], \
		&(ctl).buf[(n) + (m)], \
		((ctl).len - (n)) * VEC_ELSIZE(ctl)); \
} while (0)
#define VEC_REMOVE(ctl,n) VEC_REMOVEN(ctl,n,1)

#define VEC_INSERT1(ctl,n) \
do { \
	VEC_ADD1(ctl); \
	memmove( \
		&(ctl).buf[(n) + 1], \
		&(ctl).buf[n], \
		((ctl).len - (n) - 1) * VEC_ELSIZE(ctl)); \
} while (0)
#define VEC_INSERT(ctl,n,val) \
do { \
	VEC_INSERT1(ctl,n); \
	(ctl).buf[n] = (val); \
} while (0)

#define VEC_INSERTN(ctl,n,m) \
do { \
	VEC_ADDN(ctl,m); \
	memmove( \
		&(ctl).buf[(n) + (m)], \
		&(ctl).buf[n], \
		((ctl).len - (n) - (m)) * VEC_ELSIZE(ctl)); \
} while (0)

#define VEC_ZERO(ctl) \
do { \
	if ((ctl).buf) \
		memset((ctl).buf,0,(ctl).len * VEC_ELSIZE(ctl)); \
} while (0)

#define VEC_FREE(ctl) \
do { \
	free((ctl).buf); \
	memset(&(ctl), 0, sizeof(ctl)); \
} while (0)

#define VEC_LENGTH(ctl) ((ctl).len)
#define VEC_BUF(ctl,num) ((ctl).buf[num])

#define VEC_FOR(ctl,it) for (size_t it = 0;it < VEC_LENGTH((ctl));++it)
