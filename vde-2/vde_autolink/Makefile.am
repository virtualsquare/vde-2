AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libvdemgmt
bin_PROGRAMS = vde_autolink
vde_autolink_SOURCES = vde_autolink.c
vde_autolink_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdemgmt/libvdemgmt.la
vde_autolink_LDFLAGS = -Wl,-ldl

