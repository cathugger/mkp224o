#!/bin/sh
set -eux

V=$1

D=$(realpath "$0")
D=$(dirname "$D")
cd "$D"

mkdir -p build

export WINEARCH=win64
export WINEPREFIX=$(realpath ./build/winepfx)
OPATH=$PATH

rm -rf out
mkdir -p out

# prepare source
SV=mkp224o-$V
SO=$(realpath ./out/$SV)
git clone ../../ "$SO"
cd "$SO"
rm -rf .git
./autogen.sh
echo v$V > version.txt
cd ../..

# build windows bins
B=$(realpath ./build)
for w in x86_64 i686
do
	cd "$B"
	rm -rf $w
	mkdir $w
	cd $w
	p=$w-w64-mingw32

	case $w in
		i686)
			CFLAGS="-march=i686 -mtune=generic"
			W=32
			;;
		x86_64)
			CFLAGS="-march=x86-64 -mtune=generic"
			W=64
			;;
	esac
	CFLAGS="-O3 $CFLAGS -fomit-frame-pointer"

	export PATH=/usr/$p/bin:$OPATH
	../../out/$SV/configure --enable-regex --enable-donna --with-pcre2="/usr/$p/bin/pcre2-config" CC="${p}-gcc" CFLAGS="$CFLAGS"
	make main util
	$p-strip mkp224o.exe
	$p-strip calcest.exe
	cd ..

	BO="$SO-w$W"
	mkdir -p "$BO"
	cp $w/mkp224o.exe "$BO/"
	cp $w/calcest.exe "$BO/"
	cd "$BO"
	$p-ldd mkp224o.exe | grep -v 'not found' | awk '{print $3}' | xargs -r cp -v -t ./
done
export PATH=$OPATH

# compress stuff
cd "$D/out"
export TZ=UTC

tar --portability --no-acls --no-selinux --no-xattrs --owner root:0 --group=root:0 --sort=name -c -f $SV.tar $SV
zopfli -c $SV.tar > $SV.tar.gz
zstd -19 -f $SV.tar -o $SV.tar.zst
rm $SV.tar

zip -9 -X -r $SV-w32.zip $SV-w32
zip -9 -X -r $SV-w64.zip $SV-w64

