bin_PROGRAMS = vdeq
vdeq_SOURCES = vdeq.c

INCLUDES = -I$(top_srcdir)

EXTRA_DIST = README

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdeqemu
	$(LN_S) $(DESTDIR)$(bindir)/vdeq $(DESTDIR)$(bindir)/vdeqemu
	rm -f $(DESTDIR)$(bindir)/vdeo
	$(LN_S) $(DESTDIR)$(bindir)/vdeq $(DESTDIR)$(bindir)/vdeo
	rm -f $(DESTDIR)$(bindir)/vdeoqemu
	$(LN_S) $(DESTDIR)$(bindir)/vdeq $(DESTDIR)$(bindir)/vdeoqemu

uninstall-local:
	rm -f $(bindir)/vdeqemu
