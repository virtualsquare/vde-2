
moddir = $(pkglibdir)/vde_l3

AM_LDFLAGS = -module -avoid-version -export-dynamic
AM_LIBTOOLFLAGS = --tag=disable-static

install-data-hook:
	cd "$(DESTDIR)/$(moddir)" && rm -f $(mod_LTLIBRARIES)

mod_LTLIBRARIES = pfifo.la
pfifo_la_SOURCES = pfifo.c  vde_buff.h

pfifo_la_LIBADD = $(LTLIBOBJS)

bin_PROGRAMS = vde_l3
vde_l3_SOURCES = vde_l3.c vde_buff.h
vde_l3_LDADD = $(LIBOBJS) ../libvdeplug/libvdeplug.la -ldl

