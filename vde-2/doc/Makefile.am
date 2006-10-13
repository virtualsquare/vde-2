man_MANS = dpipe.1 slirpvde.1 unixterm.1 vde_plug.1 vdeq.1 vde_switch.1 vdetaplib.1 wirefilter.1 vde_cryptcab.1
EXTRA_DIST = $(man_MANS)

install-data-hook:
	rm -f $(DESTDIR)$(mandir)/vdeqemu.1
	(cd $(DESTDIR)$(mandir) && $(LN_S) vdeq.1 vdeqemu.1)

uninstall-local:
	rm -f $(DESTDIR)$(mandir)/vdeqemu.1
