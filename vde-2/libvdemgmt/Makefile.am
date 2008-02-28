AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libvdemgmt.la

libvdemgmt_la_SOURCES = libvdemgmt.c
libvdemgmt_la_LDFLAGS = -version-number 0:0:1 -export-dynamic

libvdemgmt_la_LIBADD = $(top_srcdir)/common/libvdecommon.la

include_HEADERS = libvdemgmt.h

