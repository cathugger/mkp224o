AC_INIT(mkp224o)
# sanity check
AC_CONFIG_SRCDIR([main.c])
# C compiler
: ${CFLAGS="-O3 -march=native -fomit-frame-pointer"}
AC_PROG_CC

ed25519impl=""
AC_ARG_ENABLE([ref10],
	[AS_HELP_STRING([--enable-ref10],
		[use ref10 ed25519 implementation @<:@default=yes@:>@])],
	[
		AS_IF([test "x$ed25519impl" != "x" -a "$ed25519impl" != "ref10"],
			[AC_ERROR([only one ed25519 implementation can be defined])])
		ed25519impl="ref10"
	],
	[]
)

AC_ARG_ENABLE([amd64_51_30k],
	[AS_HELP_STRING([--enable-amd64_51_30k],
		[use amd64_51_30k ed25519 implementation @<:@default=no@:>@])],
	[
		AS_IF([test "x$ed25519impl" != "x" -a "$ed25519impl" != "amd64_51_30k"],
			[AC_ERROR([only one ed25519 implementation can be defined])])
		ed25519impl="amd64_51_30k"
	],
	[]
)

AC_ARG_ENABLE([amd64_64_24k],
	[AS_HELP_STRING([--enable-amd64_64_24k],
		[use amd64_64_24k ed25519 implementation @<:@default=no@:>@])],
	[
		AS_IF([test "x$ed25519impl" != "x" -a "$ed25519impl" != "amd64_64_24k"],
			[AC_ERROR([only one ed25519 implementation can be defined])])
		ed25519impl="amd64_64_24k"
	],
	[]
)

AS_IF([test "x$ed25519impl" == "x"],[ed25519impl=ref10])

MYDEFS=""

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

AC_SUBST(ED25519IMPL,["$ed25519impl"])
AC_SUBST(MYDEFS,["$MYDEFS"])
AC_OUTPUT(Makefile)
