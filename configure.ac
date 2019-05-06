AC_INIT(mkp224o)
# sanity check
AC_CONFIG_SRCDIR([main.c])
# C compiler
oldcflags="$CFLAGS"
AC_PROG_CC

# NOTE: this script intentionally doesn't check for small details like posix functions and hard dependencies (libsodium) so you may get errors at compilation

if test "x$oldcflags" != "x$CFLAGS"
then
	oldcflags="-O3"
	CFLAGS="-march=native"
	AC_MSG_CHECKING([whether CC supports -march=native])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
		[AC_MSG_RESULT([yes])]
		[oldcflags="$oldcflags -march=native"],
		[AC_MSG_RESULT([no])]
	)
	CFLAGS="-fomit-frame-pointer"
	AC_MSG_CHECKING([whether CC supports -fomit-frame-pointer])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
		[AC_MSG_RESULT([yes])]
		[oldcflags="$oldcflags -fomit-frame-pointer"],
		[AC_MSG_RESULT([no])]
	)
	CFLAGS="$oldcflags"
fi

nopie=""

oldcflags="$CFLAGS"
CFLAGS="-nopie -Werror"
AC_MSG_CHECKING([whether CC supports -nopie])
AC_LINK_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
    [nopie="-nopie"],
    [AC_MSG_RESULT([no])]
)
CFLAGS="$oldcflags"

if test "x$nopie" = "x"
then
	oldcflags="$CFLAGS"
	CFLAGS="-no-pie -Werror"
	AC_MSG_CHECKING([whether CC supports -no-pie])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([])],
		[AC_MSG_RESULT([yes])]
		[nopie="-no-pie"],
		[AC_MSG_RESULT([no])]
	)
	CFLAGS="$oldcflags"
fi

MYDEFS=""
MAINLIB=""

ed25519impl=""
AC_ARG_ENABLE([ref10],
	[AS_HELP_STRING([--enable-ref10],
		[use SUPERCOP ref10 ed25519 implementation @<:@default=no@:>@])],
	[
		AS_IF([test "x$ed25519impl" != "x" -a "$ed25519impl" != "ref10"],
			[AC_ERROR([only one ed25519 implementation can be defined])])
		ed25519impl="ref10"
	],
	[]
)

AC_ARG_ENABLE([amd64-51-30k],
	[AS_HELP_STRING([--enable-amd64-51-30k],
		[use SUPERCOP amd64-51-30k ed25519 implementation @<:@default=no@:>@])],
	[
		AS_IF([test "x$ed25519impl" != "x" -a "$ed25519impl" != "amd64_51_30k"],
			[AC_ERROR([only one ed25519 implementation can be defined])])
		ed25519impl="amd64_51_30k"
	],
	[]
)

AC_ARG_ENABLE([amd64-64-24k],
	[AS_HELP_STRING([--enable-amd64-64-24k],
		[use SUPERCOP amd64-64-24k ed25519 implementation @<:@default=no@:>@])],
	[
		AS_IF([test "x$ed25519impl" != "x" -a "$ed25519impl" != "amd64_64_24k"],
			[AC_ERROR([only one ed25519 implementation can be defined])])
		ed25519impl="amd64_64_24k"
	],
	[]
)

AC_ARG_ENABLE([donna],
	[AS_HELP_STRING([--enable-donna],
		[use ed25519-donna implementation @<:@default=yes@:>@])],
	[
		AS_IF([test "x$ed25519impl" != "x" -a "$ed25519impl" != "donna"],
			[AC_ERROR([only one ed25519 implementation can be defined])])
		ed25519impl="donna"
	],
	[]
)

AC_ARG_ENABLE([donna-sse2],
	[AS_HELP_STRING([--enable-donna-sse2],
		[use ed25519-donna SSE2 implementation @<:@default=no@:>@])],
	[
		AS_IF([test "x$ed25519impl" != "x" -a "$ed25519impl" != "donna-sse2"],
			[AC_ERROR([only one ed25519 implementation can be defined])])
		ed25519impl="donna-sse2"
	],
	[]
)

# default
AS_IF([test "x$ed25519impl" == "x"],[ed25519impl="donna"])

if test "$ed25519impl" = "donna-sse2"
then
	ed25519impl="donna"
	MYDEFS="$MYDEFS -DED25519_SSE2"
	CFLAGS="$CFLAGS -msse2"
fi



AC_ARG_ENABLE([intfilter],
	[AS_HELP_STRING([--enable-intfilter@<:@=(32|64|128|native)@:>@],
		[use integers of specific size @<:@default=64@:>@ for filtering. faster but limits filter length to: 6 for 32-bit, 12 for 64-bit, 24 for 128-bit @<:@default=no@:>@])],
	[], [enable_intfilter=no]
)
AC_ARG_ENABLE([intfilter32],
	[AS_HELP_STRING([--enable-intfilter32], [deprecated. use --enable-intfilter=32 instead])],
	[enable_intfilter=32]
	[AC_MSG_WARN([--enable-intfilter32 option is deprecated. use --enable-intfilter=32 instead])],
	[]
)
case "$enable_intfilter" in
32)
	intfiltertype="u32"
	;;
64|yes)
	intfiltertype="u64"
	;;
128)
	intfiltertype="unsigned __int128"
	;;
native)
	intfiltertype="size_t"
	;;
no|"")
	intfiltertype=""
	;;
*)
	AC_MSG_WARN([unrecognised intfilter type: $enable_intfilter])
	intfiltertype=""
	;;
esac

if test -n "$intfiltertype"
then
	MYDEFS="$MYDEFS -DINTFILTER -DIFT='$intfiltertype'"
fi

AC_ARG_ENABLE([batchnum],
	[AS_HELP_STRING([--enable-batchnum=number],
		[number of elements to batch when using -B @<:@default=2048@:>@])],
	[], []
)
if test -n "$enable_batchnum" -a x"$enable_batchnum" != x"no"
then
	MYDEFS="$MYDEFS -DBATCHNUM=$enable_batchnum"
fi

cstd=""
c99=""
oldcflags="$CFLAGS"

CFLAGS="-std=c99"
AC_MSG_CHECKING([whether CC supports -std=c99])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
    [c99="yes"]
    [cstd="-std=c99"],
    [AC_MSG_RESULT([no])]
)

CFLAGS="$cstd -Wall"
AC_MSG_CHECKING([whether CC supports -Wall])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
    [cstd="$cstd -Wall"],
    [AC_MSG_RESULT([no])]
)

# (negative) detection on clang fails without -Werror
CFLAGS="$cstd -Wno-maybe-uninitialized -Werror"
AC_MSG_CHECKING([whether CC supports -Wno-maybe-uninitialized])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
    [cstd="$cstd -Wno-maybe-uninitialized"],
    [AC_MSG_RESULT([no])]
)

if test "x$c99" = "xyes" -a "x$ed25519impl" != "xdonna" -a "x$enable_intfilter" != "x128"
then
	CFLAGS="$cstd -pedantic"
	AC_MSG_CHECKING([whether CC supports -pedantic])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
		[AC_MSG_RESULT([yes])]
		[cstd="$cstd -pedantic"],
		[AC_MSG_RESULT([no])]
	)
fi

CFLAGS="$cstd -Wno-format -Wno-pedantic-ms-format -Werror"
AC_MSG_CHECKING([whether CC supports and needs -Wno-format -Wno-pedantic-ms-format])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#ifndef _WIN32
#error wants windows
#endif]], [])],
	[AC_MSG_RESULT([yes])]
	[cstd="$cstd -Wno-format -Wno-pedantic-ms-format"],
	[AC_MSG_RESULT([no])]
)

if test "x$ed25519impl" = "xdonna"
then
	CFLAGS="$cstd -Wno-unused-function -Werror"
	AC_MSG_CHECKING([whether CC supports -Wno-unused-function])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
		[AC_MSG_RESULT([yes])]
		[cstd="$cstd -Wno-unused-function"],
		[AC_MSG_RESULT([no])]
	)
fi

CFLAGS="$oldcflags"

AC_ARG_ENABLE([binfilterlen],
	[AS_HELP_STRING([--enable-binfilterlen=VAL],
		[set binary string filter length (if you don't use intfilter) @<:@default=32@:>@])],
	[], [enable_binfilterlen=no]
)
if test "x$enable_binfilterlen" != "xyes" -a "x$enable_binfilterlen" != "xno"
then
	MYDEFS="$MYDEFS -DBINFILTERLEN=$enable_binfilterlen"
fi

AC_ARG_ENABLE([binsearch],
	[AS_HELP_STRING([--enable-binsearch],
		[enable binary search algoritm; MUCH faster if there are a lot of filters @<:@default=no@:>@])],
	[], [enable_binsearch=no]
)
if test "x$enable_binsearch" = "xyes"
then
	MYDEFS="$MYDEFS -DBINSEARCH"
fi

AC_ARG_ENABLE([besort],
	[AS_HELP_STRING([--enable-besort],
		[force intfilter binsearch case to use big endian sorting and not omit masks from filters; useful if your filters aren't of same length @<:@default=no@:>@])],
	[], [enable_besort=no]
)
if test "x$enable_besort" = "xyes"
then
	MYDEFS="$MYDEFS -DBESORT"
fi

AC_ARG_ENABLE([statistics],
	[AS_HELP_STRING([--enable-statistics],
		[collect statistics @<:@default=yes@:>@])],
	[], [enable_statistics=yes]
)
if test "x$enable_statistics" = "xyes"
then
	MYDEFS="$MYDEFS -DSTATISTICS"
fi

AC_ARG_WITH([pcre2],[AC_HELP_STRING([--with-pcre2],[pcre2-config executable @<:@default=pcre2-config@:>@])],[],[with_pcre2="pcre2-config"])

AC_ARG_ENABLE([regex],[AC_HELP_STRING([--enable-regex],[whether to enable regex engine. currently possible values are "pcre2" and "yes" which defaults to "pcre2" @<:@default=no@:>@])],[],[enable_regex=no])
case "$enable_regex" in
no|"")
	;;
yes|pcre2)
	AC_MSG_CHECKING([pcre2])
	V=""
	if test "$with_pcre2" != "yes"
	then
		V=`"$with_pcre2" --version 2>/dev/null`
	fi
	if test -n "$V"
	then
		AC_MSG_RESULT([$V])
		MYDEFS="$MYDEFS -DPCRE2FILTER"
		CF=`"$with_pcre2" --cflags`
		if test -n "$CF"
		then
			CFLAGS="$CFLAGS $CF"
		fi
		LF=`"$with_pcre2" --libs8`
		if test -n "$LF"
		then
			MAINLIB="$MAINLIB $LF"
		fi
	else
		AC_MSG_RESULT([not found])
		AC_ERROR([pcre2-config cannot be executed])
	fi
	;;
*)
	AC_MSG_WARN([unrecognised regex engine type: $enable_regex])
	;;
esac


AC_MSG_CHECKING([whether ARGON2ID13 is supported by libsodium])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[#include <sodium/crypto_pwhash.h>]],
		[[int alg = crypto_pwhash_ALG_ARGON2ID13;(void) alg;]]
	)],
	[AC_MSG_RESULT([yes])]
	[MYDEFS="$MYDEFS -DPASSPHRASE"],
	[AC_MSG_RESULT([no])]
)


# recreate dir tree, because otherwise gcc will fuck up
(cd "$srcdir" && find ed25519 -type d) | xargs mkdir -p

AC_SUBST(CSTD,["$cstd"])
AC_SUBST(ED25519IMPL,["$ed25519impl"])
AC_SUBST(MYDEFS,["$MYDEFS"])
AC_SUBST(MAINLIB,["$MAINLIB"])
AC_SUBST(NOPIE,["$nopie"])
AC_SUBST(SRCDIR,["$srcdir"])
AC_OUTPUT(Makefile)
