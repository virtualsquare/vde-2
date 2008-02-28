bin_PROGRAMS = unixcmd
unixcmd_SOURCES = unixcmd.c
unixcmd_LDADD = ../compat/libvdecompat.la ../utils/libvdeutils.la
unixcmd_LDFLAGS = -Wl,-ldl

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdecmd
	(cd $(DESTDIR)$(bindir) && $(LN_S) unixcmd vdecmd)

uninstall-local:
	rm -f $(bindir)/vdecmd
