bin_PROGRAMS = unixcmd
unixcmd_SOURCES = unixcmd.c ../utils/cmdparse.c
unixcmd_LDADD = $(LIBOBJS)

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdecmd
	(cd $(DESTDIR)$(bindir) && $(LN_S) unixcmd vdecmd)

