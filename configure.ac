# Copyright 2015 James Geboski <jgeboski@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_INIT(
    [purple-facebook],
    [6e3ee8e18697],
    [https://github.com/jgeboski/purple-facebook/issues],
    [purple-facebook],
    [https://github.com/jgeboski/purple-facebook],
    []
)

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([subdir-objects])

AC_PROG_CC
AM_PROG_CC_C_O

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Define PKG_CHECK_VAR() for pkg-config < 0.28
m4_define_default(
    [PKG_CHECK_VAR],
    [AC_REQUIRE([PKG_PROG_PKG_CONFIG])
     AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])
     AS_IF([test -z "$$1"], [$1=`$PKG_CONFIG --variable="$3" "$2"`])
     AS_IF([test -n "$$1"], [$4], [$5])]
)

AC_ARG_ENABLE(
    [debug],
    [AS_HELP_STRING(
        [--enable-debug],
        [Enable debugging features]
    )],
    [DEBUG="yes"],
    [DEBUG="no"]
)

AC_ARG_ENABLE(
    [minimal-flags],
    [AS_HELP_STRING(
        [--enable-minimal-flags],
        [Disable internal CFLAGS which are not required]
    )],
    [MINIMAL_FLAGS="yes"],
    [MINIMAL_FLAGS="no"]
)

AS_IF(
    [test "x$DEBUG" == "xyes"],
    [AS_IF(
        [test "x$MINIMAL_FLAGS" == "xno"],
        [CFLAGS="$CFLAGS -Wall -Wformat-nonliteral -g -O0"
         CFLAGS="$CFLAGS -Wno-unused-variable -Wno-unused-but-set-variable"]
    )]
)

AC_ARG_WITH(
    [plugindir],
    [AS_HELP_STRING(
        [--with-plugindir],
        [libpurple plugin directory]
    )],
    [PURPLE_PLUGINDIR="$with_plugindir"]
)

PKG_CHECK_MODULES([GLIB],   [glib-2.0      >= 2.32.0])
PKG_CHECK_MODULES([JSON],   [json-glib-1.0 >= 0.14.0])
PKG_CHECK_MODULES([PURPLE], [purple        <= 3])
PKG_CHECK_MODULES([ZLIB],   [zlib])
PKG_CHECK_VAR([GLIB_GENMARSHAL], [glib-2.0], [glib_genmarshal])

AS_IF(
    [test -z "$PURPLE_PLUGINDIR"],
    [PKG_CHECK_VAR(
        [PURPLE_PLUGINDIR],
        [purple],
        [plugindir],
        [PURPLE_PLUGINDIR="$PURPLE_PLUGINDIR"],
        [PURPLE_PLUGINDIR="$libdir/purple-2"]
    )]
)

PLUGIN_CFLAGS="-I`pwd`/$srcdir/include -I`pwd`/$srcdir/pidgin"
PLUGIN_CFLAGS="$PLUGIN_CFLAGS -DPURPLE_PLUGINS -include purple-compat.h"
AC_SUBST([PLUGIN_CFLAGS])

AM_CONDITIONAL([STATIC_FACEBOOK], false)
AC_SUBST([PLUGIN_LDFLAGS], [-avoid-version])
AC_SUBST([PURPLE_LIBS],    ["$GLIB_LIBS $JSON_LIBS $PURPLE_LIBS $ZLIB_LIBS"])

AC_CONFIG_FILES([Makefile pidgin/libpurple/protocols/facebook/Makefile])
AC_OUTPUT
