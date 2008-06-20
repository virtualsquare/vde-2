SUBDIRS = \
	common \
	lib \
	vde_switch \
	vde_over_ns \
	vde_l3 \
	kvde_switch \
	slirpvde

bin_PROGRAMS = \
	dpipe \
	unixcmd \
	unixterm \
	vde_autolink \
	vde_plug2tap \
	vde_plug \
	vdeq \
	wirefilter

sbin_PROGRAMS = \
	vde_tunctl

if CAN_MAKE_LIBVDETAP
  SUBDIRS += vdetaplib
  bin_PROGRAMS += vde_tunctl
endif

if ENABLE_CRYPTCAB
  SUBDIRS += vde_cryptcab
endif

AM_CPPFLAGS = -I$(top_srcdir)/include
LDADD = common/libvdecommon.la -lm

vde_autolink_LDADD = $(LDADD) lib/libvdemgmt.la
vde_plug2tap_LDADD =$(LDADD) lib/libvdeplug.la
vde_plug_LDADD = $(LDADD) lib/libvdeplug.la
vdeq_LDADD = $(LDADD) lib/libvdeplug.la
wirefilter_LDADD = $(LDADD) lib/libvdeplug.la

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdecmd
	(cd $(DESTDIR)$(bindir) && $(LN_S) unixcmd vdecmd)
	rm -f $(DESTDIR)$(bindir)/vdeqemu $(DESTDIR)$(bindir)/vdekvm
	(cd $(DESTDIR)$(bindir) && $(LN_S) vdeq vdeqemu && $(LN_S) vdeq vdekvm )
	rm -f $(DESTDIR)$(bindir)/vdeo
	rm -f $(DESTDIR)$(bindir)/vdeoqemu

uninstall-local:
	rm -f $(bindir)/vdecmd
	rm -f $(bindir)/vdeqemu $(bindir)/vdekvm

