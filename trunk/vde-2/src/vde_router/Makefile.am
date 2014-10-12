
moddir = $(pkglibdir)/vde_router

AM_LDFLAGS = -module -avoid-version -export-dynamic
AM_LIBTOOLFLAGS = --tag=disable-static
AM_CPPFLAGS = -I$(top_srcdir)/include

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS += -pg --coverage
endif

bin_PROGRAMS = vde_router
vde_router_SOURCES = \
	rbtree.c \
	rbtree.h \
	vde_headers.h \
	vde_router.c \
	vde_router.h \
	vder_arp.c \
	vder_arp.h \
	vder_datalink.c \
	vder_datalink.h \
	vder_dhcp.c \
	vder_dhcp.h \
	vder_icmp.c \
	vder_icmp.h \
	vder_olsr.c \
	vder_olsr.h \
	vder_packet.c \
	vder_packet.h \
	vder_queue.c \
	vder_queue.h \
	vder_udp.c \
	vder_udp.h

vde_router_LDADD = $(top_builddir)/src/common/libvdecommon.la $(top_builddir)/src/lib/libvdeplug.la -lpthread
