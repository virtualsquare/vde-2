bin_PROGRAMS = vdeq
vdeq_SOURCES = vdeq.c

INCLUDES = -I$(top_srcdir)

EXTRA_DIST = README

install-exec-hook:
	rm -f $(bindir)/vdeqemu
	ln -s $(bindir)/vdeq $(bindir)/vdeqemu

uninstall-local:
	rm -f $(bindir)/vdeqemu
