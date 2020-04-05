#!/bin/bash
set -e

GITREV=$(git rev-parse --short=7 HEAD)
FULLVERS="$(date +%Y%m%d)-$(cat RELEASE_VERSION)-${GITREV}-${TRAVIS_BUILD_NUMBER}"

CC="i686-w64-mingw32-gcc" \
DLL_LD_FLAGS="-static-libgcc" \
make -f Makefile.mingw \
    install \
    GLIB_GENMARSHAL="glib-genmarshal" \
    PLUGIN_VERSION="${FULLVERS}" \
    WIN32_TREE_TOP="win32-dev/pidgin-2.10.11"
