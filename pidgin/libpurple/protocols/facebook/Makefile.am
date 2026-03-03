EXTRA_DIST = \
	Makefile.mingw

pkgdir = @PURPLE_PLUGINDIR@

FACEBOOKSOURCES = \
	api.c \
	api.h \
	data.c \
	data.h \
	facebook.h \
	facebook.c \
	http.c \
	http.h \
	id.h \
	json.c \
	json.h \
	mqtt.c \
	mqtt.h \
	thrift.c \
	thrift.h \
	util.c \
	util.h

AM_CFLAGS = $(st)

libfacebook_la_LDFLAGS = -module @PLUGIN_LDFLAGS@

if STATIC_FACEBOOK

st = -DPURPLE_STATIC_PRPL
noinst_LTLIBRARIES     = libfacebook.la
libfacebook_la_SOURCES = $(FACEBOOKSOURCES)
libfacebook_la_CFLAGS  = $(AM_CFLAGS)

else

st =
pkg_LTLIBRARIES        = libfacebook.la
libfacebook_la_SOURCES = $(FACEBOOKSOURCES)
libfacebook_la_LIBADD  = @PURPLE_LIBS@ $(JSON_LIBS)

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS) \
	$(JSON_CFLAGS) \
	$(GPLUGIN_CFLAGS) \
	$(DEBUG_CFLAGS)
