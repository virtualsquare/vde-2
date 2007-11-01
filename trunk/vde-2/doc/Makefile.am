static_mans = dpipe.1 slirpvde.1 unixterm.1 vde_plug.1 vdeq.1 vde_switch.1 wirefilter.1 vde_cryptcab.1 vde_plug2tap.1 vde_over_ns.1 vde_l3.1 vde_tunctl.8
man_MANS = $(static_mans) vdetaplib.1

vdecmddir = $(sysconfdir)/vde2/
dist_vdecmd_DATA = vdecmd
libvdemgmtdir = $(sysconfdir)/vde2/libvdemgmt/
dist_libvdemgmt_DATA = libvdemgmt/asyncrecv.rc libvdemgmt/closemachine.rc \
		       libvdemgmt/openmachine.rc libvdemgmt/sendcmd.rc


EXTRA_DIST = $(static_mans) vdetaplib.1.in freebsd_tap vde_autolink-howto


vdetaplib.1: vdetaplib.1.in
	sed 's/%LIBEXECDIR%/$(subst /,\/,$(libexecdir))/g' vdetaplib.1.in > vdetaplib.1

install-data-hook:
	rm -f $(DESTDIR)$(mandir)/man1/vdeqemu.1
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) vdeq.1 vdeqemu.1)

uninstall-local:
	rm -f $(DESTDIR)$(mandir)/man1/vdeqemu.1

clean:
	rm -f vdetaplib.1
