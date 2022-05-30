#ifndef COMPAT_H
#define COMPAT_H

#if defined(_WIN32) && defined(__GNUC__)
#define SYSVABI __attribute__((sysv_abi))
#else
#define SYSVABI
#endif

#endif
