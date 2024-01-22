#!/bin/sh

if [ x"$1" = x ]
then
	echo "Usage: $0 key-id" >&2
	exit 1
fi

D=$(realpath "$0")
D=$(dirname "$D")
cd "$D"

export TZ=UTC

cd out

gpg --detach-sign -u "$1" mkp224o-*-src.tar.gz
gpg --detach-sign -u "$1" mkp224o-*-src.tar.zst
gpg --detach-sign -u "$1" mkp224o-*-w32.zip
gpg --detach-sign -u "$1" mkp224o-*-w64.zip
