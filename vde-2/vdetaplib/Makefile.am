pkglib_LTLIBRARIES = libvdetap.la
libexec_PROGRAMS = vdetap

libvdetap_la_SOURCES = libvdetap.c
libvdetap_la_LDFLAGS = -avoid-version -export-dynamic -module -Wl,-init -Wl,libvdetap_init -Wl,-fini -Wl,libvdetap_fini

AM_CPPFLAGS=-DLIBEXECDIR=\"$(libexecdir)\"

vdetap_SOURCES = vdetap.c
vdetap_LDADD = ../libvdeplug/libvdeplug.la
