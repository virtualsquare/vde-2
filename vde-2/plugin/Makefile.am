moddir = $(pkglibdir)/plugins


AM_LDFLAGS = -module -avoid-version -export-dynamic
AM_LIBTOOLFLAGS = --tag=disable-static
AM_CPPFLAGS = -I$(top_srcdir)/include

if ENABLE_EXPERIMENTAL
  AM_CPPFLAGS += -DDEBUGOPT -DPORTCOUNTERS -DVDEPLUGIN
endif

#install-data-hook:
#	cd "$(DESTDIR)/$(moddir)" && rm -f $(mod_LTLIBRARIES)


mod_LTLIBRARIES = dump.la

dump_la_SOURCES = dump.c vdeplugin.h
dump_la_LIBADD = $(top_srcdir)/common/libvdecommon.la

if ENABLE_PCAP
mod_LTLIBRARIES += pdump.la
pdump_la_SOURCES = pdump.c vdeplugin.h
pdump_la_LIBADD = $(top_srcdir)/common/libvdecommon.la -lpcap
endif
