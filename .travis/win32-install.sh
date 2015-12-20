#!/bin/bash
set -e

wget -nv -nc -P downloads/mingw-4.7.2 \
    http://downloads.sourceforge.net/mingw/MinGW/Base/gcc/Version4/gcc-4.7.2-1/libssp-4.7.2-1-mingw32-dll-0.tar.lzma

wget -nv -nc -P downloads/glib-2.28.8 \
    http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/gettext-runtime-dev_0.18.1.1-2_win32.zip \
    http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/zlib-dev_1.2.5-2_win32.zip \
    http://ftp.gnome.org/pub/gnome/binaries/win32/glib/2.28/glib-dev_2.28.8-1_win32.zip

wget -nv -nc -P downloads \
    https://github.com/jgeboski/purple-facebook/releases/download/downloads/json-glib-0.14.tar.gz \
    https://github.com/jgeboski/purple-facebook/releases/download/downloads/pidgin-2.10.11.tar.gz

for DIR in glib-2.28.8 mingw-4.7.2 .; do
    mkdir -p "win32-dev/${DIR}"
    find "downloads/${DIR}" -maxdepth 1 -iname '*.tar.*' \
        -exec tar xf "{}" -C "win32-dev/${DIR}" \;
    find "downloads/${DIR}" -maxdepth 1 -iname '*.zip' \
        -exec unzip -qq "{}" -d "win32-dev/${DIR}" \;
done

ln -sf ../../mingw-4.7.2/bin/libssp-0.dll win32-dev/glib-2.28.8/lib/libssp.dll
