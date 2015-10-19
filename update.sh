#!/bin/sh

URL="https://bitbucket.org/pidgin/main"
HASHG=$(_TMP_=$(type hg 2>&1); echo $?)

if test "$HASHG" != "0"; then
    echo "hg (mercurial) not found in PATH" >&2
    exit $HASHG
fi

test -z "$srcdir" && srcdir=$(dirname "$0")
test -z "$srcdir" && srcdir=.

cd "$srcdir"
REVISION=$(cat VERSION)

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
cd pidgin

for patch in $(ls -1 "$patchdir"); do
    patch -p1 -i "$patchdir/$patch"
done
