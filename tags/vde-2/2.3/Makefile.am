SUBDIRS = include src man doc
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = Changelog COPYING COPYING.libvdeplug COPYING.slirpvde INSTALL README

DISTCHECK_CONFIGURE_FLAGS = --enable-experimental

extraclean: distclean
	rm -f \
	aclocal.m4 \
	autom4te.cache \
	autoscan.log \
	configure.scan \
	configure \
	depcomp \
	install-sh \
	Makefile.in \
	config.guess \
	config.sub \
	ltmain.sh \
	missing \
	compile \
	include/config.h.in* \
	vde2-*.tar.gz \
	vde2-*.tar.bz2 \
	`find . -name Makefile.in`
