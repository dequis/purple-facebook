#!/bin/bash
set -e

CC="i686-w64-mingw32-gcc" \
DLL_LD_FLAGS="-static-libgcc" \
make -f Makefile.mingw \
    install \
    GLIB_GENMARSHAL="glib-genmarshal" \
    PLUGIN_VERSION="${VERSION}" \
    WIN32_TREE_TOP="win32-dev/pidgin-2.10.11"
