AC_INIT(mkp224o)
# sanity check
AC_CONFIG_SRCDIR([main.c])
# C compiler
oldcflags="$CFLAGS"
AC_PROG_CC

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

cstd=""
oldcflags="$CFLAGS"
CFLAGS="-std=c99"
AC_MSG_CHECKING([whether CC supports -std=c99])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
    [cstd="-std=c99"],
    [AC_MSG_RESULT([no])]
)
CFLAGS="$oldcflags"

nopie=""

oldcflags="$CFLAGS"
CFLAGS="-nopie"
AC_MSG_CHECKING([whether CC supports -nopie])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
    [nopie="-nopie"],
    [AC_MSG_RESULT([no])]
)
CFLAGS="$oldcflags"

if test "x$nopie" = "x"
then
	oldcflags="$CFLAGS"
	CFLAGS="-no-pie"
	AC_MSG_CHECKING([whether CC supports -no-pie])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
		[AC_MSG_RESULT([yes])]
		[nopie="-no-pie"],
		[AC_MSG_RESULT([no])]
	)
	CFLAGS="$oldcflags"
fi

MYDEFS=""

ed25519impl=""
AC_ARG_ENABLE([ref10],
	[AS_HELP_STRING([--enable-ref10],
		[use SUPERCOP ref10 ed25519 implementation @<:@default=yes@:>@])],
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
		[use ed25519-donna implementation @<:@default=no@:>@])],
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

AS_IF([test "x$ed25519impl" == "x"],[ed25519impl=ref10])

if test "$ed25519impl" = "donna-sse2"
then
	ed25519impl="donna"
	MYDEFS="$MYDEFS -DED25519_SSE2"
	CFLAGS="$CFLAGS -msse2"
fi

AC_ARG_ENABLE([intfilter],
	[AS_HELP_STRING([--enable-intfilter],
		[use 64bit integers for filtering. faster but limits filter length @<:@default=no@:>@])],
	[], [enable_intfilter=no]
)
if test "x$enable_intfilter" = "xyes"
then
	MYDEFS="$MYDEFS -DINTFILTER"
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

AC_SUBST(CSTD,["$cstd"])
AC_SUBST(ED25519IMPL,["$ed25519impl"])
AC_SUBST(MYDEFS,["$MYDEFS"])
AC_SUBST(NOPIE,["$nopie"])
AC_OUTPUT(Makefile)
