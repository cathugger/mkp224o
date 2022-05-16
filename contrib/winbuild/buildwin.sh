#!/bin/sh
set -e

D=$(realpath "$0")
D=$(dirname "$D")
cd "$D"

export WINEARCH=win64
export WINEPREFIX=$(realpath ./winepfx)
OPATH=$PATH

for w in x86_64 i686
do
	rm -rf "$w"
	mkdir "$w"
	cd "$w"
	p=$w-w64-mingw32

	case $w in
		i686)
			CFLAGS="-march=i686 -mtune=generic"
			;;
		x86_64)
			CFLAGS="-march=x86-64 -mtune=generic"
			;;
	esac
	CFLAGS="-O3 $CFLAGS -fomit-frame-pointer"

	export PATH=/usr/$p/bin:$OPATH
	../../../configure --enable-regex --enable-donna --with-pcre2="/usr/$p/bin/pcre2-config" CC="$p-gcc" CFLAGS="$CFLAGS"
	make
	cd ..
done
