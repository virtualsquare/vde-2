
moddir = $(pkglibdir)/vde_router

AM_LDFLAGS = -module -avoid-version -export-dynamic
AM_LIBTOOLFLAGS = --tag=disable-static
AM_CPPFLAGS = -I$(top_srcdir)/include

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS += -pg --coverage
endif

bin_PROGRAMS = vde_router
vde_router_SOURCES = rbtree.h  vde_headers.h  vder_arp.h  vder_datalink.h  vder_icmp.h \
    vde_router.h  vder_packet.h	vder_queue.h rbtree.c  vder_arp.c  vder_datalink.c \
    vder_icmp.c  vde_router.c  vder_packet.c  vder_queue.c vder_udp.c vder_dhcp.c

vde_router_LDADD = $(top_builddir)/src/common/libvdecommon.la $(top_builddir)/src/lib/libvdeplug.la -lpthread
