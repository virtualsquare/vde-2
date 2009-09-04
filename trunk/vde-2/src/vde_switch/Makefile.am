bin_PROGRAMS = vde_switch
vde_switch_SOURCES = \
	hash.c \
	hash.h \
	port.c \
	port.h \
	vde_switch.c \
	switch.h \
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

vde_switch_LDADD = $(top_srcdir)/src/common/libvdecommon.la

AM_CPPFLAGS = -I$(top_srcdir)/include \
              -DSYSCONFDIR="\"$(sysconfdir)\"" -DLOCALSTATEDIR="\"$(localstatedir)\""
AM_CFLAGS = -Wall

if ENABLE_PROFILE
  AM_CFLAGS += -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

if DARWIN_GCC
 EXP_CFLAGS = -dynamic
else
 EXP_CFLAGS = -rdynamic
endif

DIST_SUBDIRS = plugins
if ENABLE_EXPERIMENTAL
  SUBDIRS = plugins
  AM_CFLAGS += $(EXP_CFLAGS)
  AM_CPPFLAGS += -DDEBUGOPT -DPORTCOUNTERS -DVDEPLUGIN
endif

