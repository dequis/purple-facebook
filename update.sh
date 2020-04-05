#!/bin/sh

set -e

URL="https://keep.imfreedom.org/pidgin/pidgin"
HASHG=$(_TMP_=$(type hg 2>&1); echo $?)

if test "$HASHG" != "0"; then
    echo "hg (mercurial) not found in PATH" >&2
    exit $HASHG
fi

test -z "$srcdir" && srcdir=$(dirname "$0")
test -z "$srcdir" && srcdir=.
test -z "$pidgindir" && pidgindir=.pidgin

cd "$srcdir"
REVISION=$(cat VERSION)

if ! test -d "$pidgindir/.hg"; then
    rm -rf "$pidgindir"
    hg clone "$URL" "$pidgindir"
fi

hg -R "$pidgindir" -v pull
hg -R "$pidgindir" -v update -C "$REVISION"
rm -rf pidgin

for FILE in $(cat MANIFEST_PIDGIN); do
    mkdir -p $(dirname "pidgin/$FILE")
    cp "$pidgindir/$FILE" "pidgin/$FILE"
done

touch $(cat MANIFEST_VOIDS)

patchdir="$(pwd)/patches"
cd pidgin

for patch in $(ls -1 "$patchdir"); do
    patch -p1 -i "$patchdir/$patch"
done
