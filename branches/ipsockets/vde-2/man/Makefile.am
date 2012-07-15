static_mans = dpipe.1 slirpvde.1 unixterm.1 vde_plug.1 vdeq.1 vde_switch.1 wirefilter.1 vde_cryptcab.1 vde_plug2tap.1 vde_over_ns.1 vde_l3.1 vde_tunctl.8 vde_autolink.1 unixcmd.1 vdeterm.1 vde_router.1
if ENABLE_PCAP
  static_mans += vde_pcapplug.1
endif
generated_mans = vdetaplib.1

man_MANS = $(static_mans) $(generated_mans)


CLEANFILES = $(generated_mans)
EXTRA_DIST = $(static_mans) vdetaplib.1.in vde_pcapplug.1

vdetaplib.1: vdetaplib.1.in
	sed 's/%PKGLIBDIR%/$(subst /,\/,$(pkglibdir))/g' \
		$(srcdir)/vdetaplib.1.in > $(builddir)/vdetaplib.1

install-data-hook:
	rm -f $(DESTDIR)$(mandir)/man1/vdeqemu.1
	rm -f $(DESTDIR)$(mandir)/man1/vdekvm.1
	rm -f $(DESTDIR)$(mandir)/man1/vdecmd.1
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) vdeq.1 vdeqemu.1)
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) vdeq.1 vdekvm.1)
	(cd $(DESTDIR)$(mandir)/man1 && $(LN_S) unixcmd.1 vdecmd.1)

uninstall-local:
	rm -f $(DESTDIR)$(mandir)/man1/vdeqemu.1
	rm -f $(DESTDIR)$(mandir)/man1/vdekvm.1
	rm -f $(DESTDIR)$(mandir)/man1/vdecmd.1

#clean:
#	rm -f vdetaplib.1
