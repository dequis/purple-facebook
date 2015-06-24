#!/bin/sh

URL="https://hg.pidgin.im/soc/2015/jgeboski/facebook"
REV="5e83f57d97f3"
HG=$(type -p hg || exit 1)

test -z "$srcdir" && srcdir=$(dirname "$0")
test -z "$srcdir" && srcdir=.

cd "$srcdir"

if ! test -d .pidgin/.hg; then
    rm -rf .pidgin
    "$HG" clone "$URL" .pidgin
fi

"$HG" -R .pidgin -v pull
"$HG" -R .pidgin -v update -C "$REV"
rm -rf pidgin

for FILE in $(cat MANIFEST_PIDGIN); do
    mkdir -p $(dirname "pidgin/$FILE")
    cp ".pidgin/$FILE" "pidgin/$FILE"
done

touch $(cat MANIFEST_VOIDS)

patchdir="$(pwd)/patches"
cd "$srcdir/pidgin"

for patch in $(ls -1 "$patchdir"); do
    patch -p1 -i "$patchdir/$patch"
done
