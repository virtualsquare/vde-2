AM_CPPFLAGS = -I$(top_srcdir)/include

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

noinst_LTLIBRARIES = libvdecommon.la

libvdecommon_la_SOURCES = cmdparse.c canonicalize.c
libvdecommon_la_LIBADD = $(LTLIBOBJS) $(LTALLOCA)
