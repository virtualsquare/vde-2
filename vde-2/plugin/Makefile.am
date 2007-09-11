moddir = $(pkglibdir)/plugins

AM_LDFLAGS = -module -avoid-version -export-dynamic
AM_LIBTOOLFLAGS = --tag=disable-static

#install-data-hook:
#	cd "$(DESTDIR)/$(moddir)" && rm -f $(mod_LTLIBRARIES)


mod_LTLIBRARIES = dump.la

dump_la_SOURCES = dump.c vdeplugin.h
dump_la_LIBADD = $(LTLIBOBJS)

if ENABLE_PCAP
mod_LTLIBRARIES += pdump.la
pdump_la_SOURCES = pdump.c vdeplugin.h
pdump_la_LIBADD = $(LTLIBOBJS) -lpcap
endif
