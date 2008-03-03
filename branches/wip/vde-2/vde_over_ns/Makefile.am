AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libvdeplug
bin_PROGRAMS = vde_over_ns
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

vde_over_ns_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdeplug/libvdeplug.la
#vde_over_ns_LDFLAGS = -Wl,-ldl
