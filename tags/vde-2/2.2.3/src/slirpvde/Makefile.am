AM_CPPFLAGS = -I$(top_srcdir)/include -DVDE
AM_CFLAGS = -g -O2

if ENABLE_PROFILE
  AM_CFLAGS += -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

bin_PROGRAMS = slirpvde

slirpvde_SOURCES = \
		   misc.c \
		   misc.h \
		   cksum.c \
		   debug.c \
		   debug.h \
		   icmp_var.h \
		   if.c \
		   if.h \
		   ip.h \
		   ip_icmp.c \
		   ip_icmp.h \
		   ip_input.c \
		   ip_output.c \
		   libslirp.h \
		   main.h \
		   mbuf.c \
		   mbuf.h \
		   sbuf.c \
		   sbuf.h \
		   slirp.c \
		   slirp_config.h \
		   slirp.h \
		   ctl.h \
		   socket.c \
		   socket.h \
		   tcp.h \
		   tcp_input.c \
		   tcpip.h \
		   tcp_output.c \
		   tcp_subr.c \
		   tcp_timer.c \
		   tcp_timer.h \
		   tcp_var.h \
		   udp.c \
		   udp.h \
		   bootp.c \
		   bootp.h \
		   tcp2unix.c \
		   tcp2unix.h \
		   slirpvde.c

slirpvde_LDADD = $(top_srcdir)/src/common/libvdecommon.la $(top_srcdir)/src/lib/libvdeplug.la
