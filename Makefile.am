ACLOCAL_AMFLAGS = -Im4
SUBDIRS         = pidgin/libpurple/protocols/facebook

EXTRA_DIST = \
	autogen.sh \
	include \
	Makefile.mingw \
	MANIFEST_PIDGIN \
	MANIFEST_VOIDS \
	patches \
	pidgin/AUTHORS \
	pidgin/COPYING \
	pidgin/COPYRIGHT \
	pidgin/share/ca-certs/GTE_CyberTrust_Global_Root.pem \
	update.sh \
	VERSION

if WITH_SSL_CERTS
sslcertsdir   = $(datadir)/purple/ca-certs
sslcerts_DATA = pidgin/share/ca-certs/GTE_CyberTrust_Global_Root.pem
endif
