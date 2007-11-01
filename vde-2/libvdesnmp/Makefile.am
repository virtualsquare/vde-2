lib_LTLIBRARIES = libvdesnmp.la

libvdesnmp_la_SOURCES = libvdesnmp.c
libvdesnmp_la_LDFLAGS = -version-number 0:0:1 -export-dynamic

libvdesnmp_la_CFLAGS = -I../libvdemgmt/ -I../plugin/

libvdesnmp_la_LIBADD = $(LTLIBOBJS)

include_HEADERS = libvdesnmp.h
