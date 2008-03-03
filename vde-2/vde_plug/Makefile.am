AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libvdeplug
bin_PROGRAMS = vde_plug

vde_plug_SOURCES = vde_plug.c 
vde_plug_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdeplug/libvdeplug.la
#vde_plug_LDFLAGS = -Wl,-ldl
