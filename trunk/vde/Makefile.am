SUBDIRS = qemu slirpvde vdetaplib bochs uml doc

AUTOMAKE_OPTIONS = foreign 1.9

EXTRA_DIST = LICENSE VERSION

bin_PROGRAMS = vde_switch dpipe vde_plug
vde_switch_SOURCES = \
		     hash.c \
		     hash.h \
		     port.c \
		     port.h \
		     vde_switch.c \
		     switch.h \
		     vde.h
dpipe_SOURCES = dpipe.c
vde_plug_SOURCES = vde_plug.c vde.h
if WANT_TUNTAP
  vde_switch_SOURCES += tuntap.c tuntap.h
endif

AM_CFLAGS = -Wall
AM_CXXFLAGS = -Wall

extraclean: distclean
	rm -rf aclocal.m4 autom4te.cache autoscan.log configure.scan config.h.in* configure depcomp install-sh Makefile.in config.guess config.sub ltmain.sh missing `find -name Makefile.in` vde-*.tar.gz
