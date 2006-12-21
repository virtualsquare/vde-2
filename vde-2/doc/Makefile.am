static_mans = dpipe.1 slirpvde.1 unixterm.1 vde_plug.1 vdeq.1 vde_switch.1 wirefilter.1 vde_cryptcab.1 vde_plug2tap.1
EXTRA_DIST = $(static_mans) vdetaplib.1.in
man_MANS = $(static_mans) vdetaplib.1

vdetaplib.1: vdetaplib.1.in
	sed 's/%LIBEXECDIR%/$(subst /,\/,$(libexecdir))/g' $< > $@

install-data-hook:
	rm -f $(DESTDIR)$(mandir)/man1/vdeqemu.1
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) vdeq.1 vdeqemu.1)

uninstall-local:
	rm -f $(DESTDIR)$(mandir)/man1/vdeqemu.1

clean:
	rm -f vdetaplib.1
