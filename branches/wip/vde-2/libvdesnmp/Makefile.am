AM_CPPFLAGS = -I$(top_srcdir)/include

lib_LTLIBRARIES = libvdesnmp.la

libvdesnmp_la_SOURCES = libvdesnmp.c
libvdesnmp_la_LDFLAGS = -version-number 0:0:1 -export-dynamic

libvdesnmp_la_CFLAGS = -I$(top_srcdir)/libvdemgmt/ -I$(top_srcdir)/plugin/

libvdesnmp_la_LIBADD = $(top_srcdir)/common/libvdecommon.la

include_HEADERS = libvdesnmp.h
