SUBDIRS = \
	common \
	lib \
	vde_switch

bin_PROGRAMS = \
	dpipe \
	unixcmd \
	vde_autolink \
	vde_plug2tap \
	vde_plug \
	wirefilter \
	vdeterm


if CAN_MAKE_LIBVDETAP
  SUBDIRS += vdetaplib
endif

if ENABLE_CRYPTCAB
  SUBDIRS += vde_cryptcab
endif

if ENABLE_VDE_OVER_NS
  SUBDIRS += vde_over_ns
endif

if ENABLE_ROUTER
  SUBDIRS += vde_router
endif

if ENABLE_PCAP
  bin_PROGRAMS += vde_pcapplug
endif

AM_CPPFLAGS = -I$(top_srcdir)/include \
               -DSYSCONFDIR="\"$(sysconfdir)\"" -DLOCALSTATEDIR="\"$(localstatedir)\""
LDADD = common/libvdecommon.la -lm

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

vde_autolink_LDADD = $(LDADD) lib/vdemgmt/libvdemgmt.la
vde_plug2tap_LDADD = $(LDADD) lib/libvdeplug.la
if ENABLE_PCAP
  vde_pcapplug_LDADD = $(LDADD) lib/libvdeplug.la -lpcap
endif
vde_plug_LDADD = $(LDADD) lib/libvdeplug.la
wirefilter_LDADD = $(LDADD) lib/libvdeplug.la
vdeterm_LDADD = $(LDADD) lib/libvdeplug.la lib/libvdehist.la

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdecmd
	(cd $(DESTDIR)$(bindir) && $(LN_S) unixcmd vdecmd)
	rm -f $(DESTDIR)$(bindir)/vdeo

uninstall-local:
	rm -f $(bindir)/vdecmd

