SUBDIRS = libvdeplug qemu slirpvde bochs uml doc dpipe wirefilter unixterm vde_plug vde_plug2tap vde_over_ns vde_l3 plugin libvdemgmt unixcmd tunctl


if CAN_MAKE_LIBVDETAP
  SUBDIRS += vdetaplib
endif

if ENABLE_CRYPTCAB
  SUBDIRS += vde_cryptcab
endif

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = LICENSE VERSION utils/open_memstream.h utils/poll.h utils/strndup.h utils/cmdparse.h

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
	bitarray.h \
	tuntap.c \
	tuntap.h

vde_switch_LDADD = $(LIBOBJS)

AM_CFLAGS = -Wall

if DARWIN_GCC
 EXP_CFLAGS = -dynamic
else
 EXP_CFLAGS = -rdynamic
endif

if ENABLE_EXPERIMENTAL
  AM_CFLAGS += $(EXP_CFLAGS)
  AM_CPPFLAGS = -DDEBUGOPT -DPORTCOUNTERS -DVDEPLUGIN
endif

extraclean: distclean
	rm -rf aclocal.m4 autom4te.cache autoscan.log configure.scan config.h.in* configure depcomp install-sh Makefile.in config.guess config.sub ltmain.sh missing `find . -name Makefile.in` vde-*.tar.gz
