AM_CPPFLAGS = -I$(top_srcdir)/include
bin_PROGRAMS = unixcmd
unixcmd_SOURCES = unixcmd.c
unixcmd_LDADD = $(top_srcdir)/common/libvdecommon.la
unixcmd_LDFLAGS = -Wl,-ldl

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdecmd
	(cd $(DESTDIR)$(bindir) && $(LN_S) unixcmd vdecmd)

uninstall-local:
	rm -f $(bindir)/vdecmd
