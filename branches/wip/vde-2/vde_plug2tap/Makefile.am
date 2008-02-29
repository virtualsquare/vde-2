AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)
bin_PROGRAMS = vde_plug2tap

vde_plug2tap_SOURCES = vde_plug2tap.c 
vde_plug2tap_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdeplug/libvdeplug.la
vde_plug2tap_LDFLAGS = -Wl,-ldl
