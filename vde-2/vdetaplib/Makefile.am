pkglib_LTLIBRARIES = libvdetap.la
libexec_PROGRAMS = vdetap

libvdetap_la_SOURCES = libvdetap.c
libvdetap_la_LDFLAGS = -avoid-version -export-dynamic -module -Wl,-init -Wl,libvdetap_init -Wl,-fini -Wl,libvdetap_fini
# vdetaplib/libvdetap.c|85| warning: dereferencing type-punned pointer will break strict-aliasing rules
libvdetap_la_CFLAGS = -fno-strict-aliasing 

AM_CPPFLAGS=-DLIBEXECDIR=\"$(libexecdir)\"

vdetap_SOURCES = vdetap.c
vdetap_LDADD = ../libvdeplug/libvdeplug.la
