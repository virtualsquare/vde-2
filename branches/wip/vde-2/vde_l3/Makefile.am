
moddir = $(pkglibdir)/vde_l3

AM_LDFLAGS = -module -avoid-version -export-dynamic
AM_LIBTOOLFLAGS = --tag=disable-static
AM_CPPFLAGS = -I$(top_srcdir)/include

#install-data-hook:
#	cd "$(DESTDIR)/$(moddir)" && rm -f $(mod_LTLIBRARIES)

mod_LTLIBRARIES = pfifo.la tbf.la bfifo.la
pfifo_la_SOURCES = pfifo.c  vde_buff.h
tbf_la_SOURCES = tbf.c  vde_buff.h
bfifo_la_SOURCES = bfifo.c  vde_buff.h

pfifo_la_LIBADD = $(top_srcdir)/common/libvdecommon.la
bfifo_la_LIBADD = $(top_srcdir)/common/libvdecommon.la
tbf_la_LIBADD = $(top_srcdir)/common/libvdecommon.la

bin_PROGRAMS = vde_l3
vde_l3_SOURCES = vde_l3.c vde_buff.h vde_l3.h
vde_l3_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdeplug/libvdeplug.la
vde_l3_LDFLAGS = -Wl,-ldl

