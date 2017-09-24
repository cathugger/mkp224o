#include <stdio.h>

static const char hext[] = "0123456789ABCDEF";
static void printhex(const char *z, size_t l)
{
	printf("[");
	for (size_t i = 0; i < l; ++i) {
		printf("%c%c", hext[*z >> 4], hext[*z & 0xF]);
		++z;
	}
	printf("]\n");
}
