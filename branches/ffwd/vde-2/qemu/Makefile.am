bin_PROGRAMS = vdeq
vdeq_SOURCES = vdeq.c
vdeq_LDADD = ../libvdeplug/libvdeplug.la


INCLUDES = -I$(top_srcdir)

EXTRA_DIST = README

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdeqemu
	(cd $(DESTDIR)$(bindir) && $(LN_S) vdeq vdeqemu)
	rm -f $(DESTDIR)$(bindir)/vdeo
	rm -f $(DESTDIR)$(bindir)/vdeoqemu

uninstall-local:
	rm -f $(bindir)/vdeqemu
