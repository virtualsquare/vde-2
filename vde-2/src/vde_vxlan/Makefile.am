moddir = $(pkglibdir)/vde_vxlan

AM_LDFLAGS =
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src/vde_switch -I.

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS += -pg --coverage
endif

bin_PROGRAMS = vde_vxlan
vde_vxlan_SOURCES = vde_vxlan.c vxlan_hash.c log.c plug.c vxlan.c
vde_vxlan_LDADD = $(top_builddir)/src/common/libvdecommon.la \
		  $(top_builddir)/src/lib/libvdeplug.la
