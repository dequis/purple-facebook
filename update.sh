#!/bin/sh

URL="https://hg.pidgin.im/soc/2015/jgeboski/facebook"
HASHG=$(_TMP_=$(type hg 2>&1); echo $?)

if test "$HASHG" != "0"; then
    echo "hg (mercurial) not found in PATH" >&2
    exit $HASHG
fi

test -z "$srcdir" && srcdir=$(dirname "$0")
test -z "$srcdir" && srcdir=.

cd "$srcdir"

if test -z "$REVISION"; then
    REVISION=$(head -n18 configure.ac | tail -n1 | tr -d '[ ],')
fi

if ! test -d .pidgin/.hg; then
    rm -rf .pidgin
    hg clone "$URL" .pidgin
fi

hg -R .pidgin -v pull
hg -R .pidgin -v update -C "$REVISION"
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
