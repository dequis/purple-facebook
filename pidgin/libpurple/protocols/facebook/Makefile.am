EXTRA_DIST = \
	Makefile.mingw

pkgdir = @PURPLE_PLUGINDIR@

FACEBOOKSOURCES = \
	facebook.h \
	facebook.c

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
libfacebook_la_LIBADD  = @PURPLE_LIBS@

endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/libpurple \
	-I$(top_builddir)/libpurple \
	$(GLIB_CFLAGS) \
	$(GPLUGIN_CFLAGS) \
	$(DEBUG_CFLAGS)
