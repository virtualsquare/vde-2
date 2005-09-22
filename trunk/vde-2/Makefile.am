SUBDIRS = qemu slirpvde vdetaplib bochs uml doc

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = LICENSE VERSION ChangeLog

bin_PROGRAMS = vde_switch dpipe vde_plug unixterm wirefilter
vde_switch_SOURCES = \
		     hash.c \
		     hash.h \
		     port.c \
		     port.h \
		     vde_switch.c \
		     switch.h \
		     vde.h \
				 sockutils.c \
				 sockutils.h \
				 qtimer.c \
				 qtimer.h \
				 datasock.c \
				 datasock.h \
				 consmgmt.c \
				 consmgmt.h \
				 fstp.c \
				 fstp.h \
				 bitarray.h
dpipe_SOURCES = dpipe.c
vde_plug_SOURCES = vde_plug.c vde.h
unixterm_SOURCES = unixterm.c
wirefilter_SOURCES = wirefilter.c
if WANT_TUNTAP
  vde_switch_SOURCES += tuntap.c tuntap.h
endif

AM_CFLAGS = -Wall
AM_CXXFLAGS = -Wall

extraclean: distclean
	rm -rf aclocal.m4 autom4te.cache autoscan.log configure.scan config.h.in* configure depcomp install-sh Makefile.in config.guess config.sub ltmain.sh missing `find -name Makefile.in` vde-*.tar.gz
