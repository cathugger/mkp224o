#include <stdio.h>

static const char hext[] = "0123456789ABCDEF";
static void printhex(const unsigned char *z,size_t l)
{
	printf("[");
	for (size_t i = 0;i < l;++i) {
		printf("%c%c",hext[*z >> 4],hext[*z & 0xF]);
		++z;
	}
	printf("]\n");
}

static void printbin(const unsigned char *z,size_t l)
{
	printf("[");
	for (size_t i = 0;i < l;++i) {
		printf("%c%c%c%c%c%c%c%c",
			hext[(*z >> 7) & 1],
			hext[(*z >> 6) & 1],
			hext[(*z >> 5) & 1],
			hext[(*z >> 4) & 1],
			hext[(*z >> 3) & 1],
			hext[(*z >> 2) & 1],
			hext[(*z >> 1) & 1],
			hext[(*z     ) & 1]);
		++z;
	}
	printf("]\n");
}
