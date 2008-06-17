AM_CPPFLAGS = -I$(top_srcdir)/include
LIBADD = $(top_srcdir)/src/common/libvdecommon.la

lib_LTLIBRARIES = \
	libvdesnmp.la \
	libvdemgmt.la \
	libvdeplug.la

libvdesnmp_la_LIBADD = $(LIBADD)
libvdesnmp_la_LDFLAGS = -version-number 0:0:1 -export-dynamic

libvdemgmt_la_LIBADD = $(LIBADD)
libvdemgmt_la_LDFLAGS = -version-number 0:0:1 -export-dynamic

libvdeplug_la_LIBADD = $(LIBADD)
libvdeplug_la_LDFLAGS = -version-number 2:1 -export-dynamic
