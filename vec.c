#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "vec.h"

void vec_add1(struct vec_basestruct *ctl,size_t sz)
{
	if (!ctl->alen) {
		ctl->alen = 8;
		if (SIZE_MAX / 8 < sz)
			ctl->alen = 1;
		ctl->buf = malloc(ctl->alen * sz);
		if (!ctl->buf)
			abort();
	} else if (ctl->len >= ctl->alen) {
		ctl->alen *= 2;
		if (SIZE_MAX / ctl->alen < sz)
			abort();
		ctl->buf = realloc(ctl->buf,ctl->alen * sz);
		if (!ctl->buf)
			abort();
	}
	++ctl->len;
}

void vec_addn(struct vec_basestruct *ctl,size_t sz,size_t n)
{
	if (!ctl->alen) {
		if (SIZE_MAX / 8 >= sz)
			ctl->alen = 8;
		else
			ctl->alen = 1;
	}
	size_t nlen = ctl->alen;
	ctl->len += n;
	while (ctl->len > nlen)
		nlen *= 2;
	if (nlen > ctl->alen) {
		ctl->alen = nlen;
		if (SIZE_MAX / nlen < sz)
			abort();
		ctl->buf = realloc(ctl->buf,nlen * sz);
		if (!ctl->buf)
			abort();
	} else if (!ctl->buf) {
		ctl->buf = malloc(ctl->alen * sz);
		if (!ctl->buf)
			abort();
	}
}
