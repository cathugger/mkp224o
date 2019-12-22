
#define WARN(test) if (!(test)) \
	fprintf(stderr, "check failed @ %d: %s\n", (int)__LINE__, #test)

#define WARNF(test) if (!(test) && ((void) fprintf(stderr, "check failed @ %d: %s\n", (int)__LINE__, #test), 1))
