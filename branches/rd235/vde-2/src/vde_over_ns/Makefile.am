AM_CPPFLAGS = -I$(top_srcdir)/include
bin_PROGRAMS = vde_over_ns

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

vde_over_ns_SOURCES = \
	vde_over_ns.c \
	dns.c \
	encode.c \
	pstack.c \
	queue.c \
	util.c \
	vde_io.c \
	dns.h \
	dns_proto.h \
	fun.h \
	pstack.h

vde_over_ns_LDADD = $(top_builddir)/src/common/libvdecommon.la $(top_builddir)/src/lib/libvdeplug/libvdeplug.la
