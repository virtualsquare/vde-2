AM_CPPFLAGS = -I$(top_srcdir)/include

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

noinst_HEADERS = af_ipn.h

bin_PROGRAMS = kvde_switch
kvde_switch_SOURCES = consmgmt.c \
					  consmgmt.h \
					  datasock.c \
					  datasock.h \
					  kvde_switch.c \
					  sockutils.c \
					  sockutils.h
kvde_switch_LDADD = $(top_builddir)/src/common/libvdecommon.la
