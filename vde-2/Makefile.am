SUBDIRS = libvdeplug qemu slirpvde bochs uml doc dpipe wirefilter unixterm vde_plug vde_plug2tap

if WANT_TUNTAP
if CAN_MAKE_LIBVDETAP
  SUBDIRS += vdetaplib
endif
endif

if ENABLE_CRYPTCAB
  SUBDIRS += vde_cryptcab
endif

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = LICENSE VERSION

bin_PROGRAMS = vde_switch
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
	packetq.c \
	packetq.h \
	bitarray.h
if WANT_TUNTAP
  vde_switch_SOURCES += tuntap.c tuntap.h
endif

if HAVE_BROKEN_POLL
  vde_switch_SOURCES += poll2select.c poll2select.h
endif

#AM_CFLAGS = -Wall 
#AM_CXXFLAGS = -Wall
AM_CFLAGS = -Wall -DDEBUGOPT
AM_CXXFLAGS = -Wall -DDEBUGOPT

extraclean: distclean
	rm -rf aclocal.m4 autom4te.cache autoscan.log configure.scan config.h.in* configure depcomp install-sh Makefile.in config.guess config.sub ltmain.sh missing `find . -name Makefile.in` vde-*.tar.gz
