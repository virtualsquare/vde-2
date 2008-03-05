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

vde_switch_LDADD = $(top_srcdir)/common/libvdecommon.la
#vde_switch_LDFLAGS = -Wl,-ldl

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall

if DARWIN_GCC
 EXP_CFLAGS = -dynamic
else
 EXP_CFLAGS = -rdynamic
endif

if ENABLE_EXPERIMENTAL
  AM_CFLAGS += $(EXP_CFLAGS)
  AM_CPPFLAGS += -DDEBUGOPT -DPORTCOUNTERS -DVDEPLUGIN
endif

