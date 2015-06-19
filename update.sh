#!/bin/sh

URL="https://hg.pidgin.im/soc/2015/jgeboski/facebook"
REV="5abaecb5a83d"
HG=$(type -p hg || exit 1)

test -z "$srcdir" && srcdir=$(dirname "$0")
test -z "$srcdir" && srcdir=.

cd "$srcdir"

if ! test -d pidgin/.hg; then
    rm -rf pidgin
    "$HG" clone "$URL" pidgin
fi

touch \
    include/plugins.h \
    include/protocol.h \
    include/protocols.h

patchdir="$(pwd)/patches"
cd "$srcdir/pidgin"

"$HG" -v pull
"$HG" -v update -C "$REV"
"$HG" -v clean --all --config extensions.purge=

for patch in $(ls -1 "$patchdir"); do
    patch -p1 -i "$patchdir/$patch"
done

rm -f \
    libpurple/connection.h \
    libpurple/conversation.h \
    libpurple/debug.h \
    libpurple/internal.h \
    libpurple/ntlm.h \
    libpurple/proxy.h \
    libpurple/request.h \
    libpurple/sslconn.h
