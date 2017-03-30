#!/bin/sh

URL="https://bitbucket.org/pidgin/main"
HASHG=$(_TMP_=$(type hg 2>&1); echo $?)
CMD=hg

if test "$HASHG" != "0"; then
    echo "hg (mercurial) not found in PATH" >&2
    HASGIT=$(_TMP_=$(type git 2>&1); echo $?)
    if test "HASGIT" != "0"; then
        echo "git not found in PATH" >&2
        exit $HASGIT
    else
        URL="https://github.com/tieto/pidgin.git"
        CMD=git
    fi
fi

test -z "$srcdir" && srcdir=$(dirname "$0")
test -z "$srcdir" && srcdir=.
test -z "$pidgindir" && pidgindir=.pidgin

cd "$srcdir"
REVISION=$(cat VERSION)

if ! test -d "$pidgindir/.$CMD"; then
    rm -rf "$pidgindir"
    $CMD clone "$URL" "$pidgindir"
fi

if [[ "$CMD" == "hg" ]]; then
    hg -R "$pidgindir" -v pull
    hg -R "$pidgindir" -v update -C "$REVISION"
elif [[ "$CMD" == "git" ]]; then
    olddir=$(pwd)
    cd $pidgindir
    git pull --force
    cd $olddir
fi
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
