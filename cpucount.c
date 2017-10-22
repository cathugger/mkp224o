#include "cpucount.h"

#ifndef BSD
#  ifndef __linux__
// FreeBSD
#    ifdef __FreeBSD__
#      undef BSD
#      define BSD
#    endif
// OpenBSD
#    ifdef __OpenBSD__
#      undef BSD
#      define BSD
#    endif
// NetBSD
#    ifdef __NetBSD__
#      undef BSD
#      define BSD
#    endif
// DragonFly
#    ifdef __DragonFly__
#      undef BSD
#      define BSD
#    endif
#  endif // __linux__
// sys/param.h may have its own define
#  ifdef BSD
#    undef BSD
#    include <sys/param.h>
#    define SYS_PARAM_INCLUDED
#    ifndef BSD
#      define BSD
#    endif
#  endif
#endif // BSD

#ifdef BSD
#  ifndef SYS_PARAM_INCLUDED
#    include <sys/param.h>
#  endif
#  include <sys/sysctl.h>
#endif

#include <unistd.h>
#include <string.h>
#include <stdio.h>

#ifdef __linux__
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
static int parsecpuinfo()
{
	unsigned char cpubitmap[128];

	memset(cpubitmap,0,sizeof(cpubitmap));

	FILE *f = fopen("/proc/cpuinfo","r");
	if (!f)
		return -1;

	char buf[8192];
	while (fgets(buf,sizeof(buf),f)) {
		// we don't like newlines
		for (char *p = buf;*p;++p) {
			if (*p == '\n') {
				*p = 0;
				break;
			}
		}
		// split ':'
		char *v = 0;
		for (char *p = buf;*p;++p) {
			if (*p == ':') {
				*p = 0;
				v = p + 1;
				break;
			}
		}
		// key padding
		size_t kl = strlen(buf);
		while (kl > 0 && (buf[kl - 1] == '\t' || buf[kl - 1] == ' ')) {
			--kl;
			buf[kl] = 0;
		}
		// space before value
		if (v) {
			while (*v && (*v == ' ' || *v == '\t'))
				++v;
		}
		// check what we need
		if (strcasecmp(buf,"processor") == 0 && v) {
			char *endp = 0;
			long n = strtol(v,&endp,10);
			if (endp && endp > v && n >= 0 && n < sizeof(cpubitmap) * 8)
				cpubitmap[n / 8] |= 1 << (n % 8);
		}
	}

	fclose(f);

	// count bits in bitmap
	int ncpu = 0;
	for (size_t n = 0;n < sizeof(cpubitmap) * 8;++n)
		if (cpubitmap[n / 8] & (1 << (n % 8)))
			++ncpu;

	return ncpu;
}
#endif

int cpucount()
{
	int ncpu;
#ifdef _SC_NPROCESSORS_ONLN
	ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu > 0)
		return ncpu;
#endif
#ifdef __linux__
	// try parsing /proc/cpuinfo
	ncpu = parsecpuinfo();
	if (ncpu > 0)
		return ncpu;
#endif
#ifdef BSD
	const int ctlname[2] = {CTL_HW,HW_NCPU};
	size_t ctllen = sizeof(ncpu);
	if (sysctl(ctlname,2,&ncpu,&ctllen,0,0) < 0)
		ncpu = -1;
	if (ncpu > 0)
		return ncpu;
#endif
	return -1;
}
