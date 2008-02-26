bin_PROGRAMS = vdeq
vdeq_SOURCES = vdeq.c
vdeq_LDADD = ../compat/libvdecompat.la ../libvdeplug/libvdeplug.la
vdeq_LDFLAGS = -Wl,-ldl


INCLUDES = -I$(top_srcdir)

EXTRA_DIST = README qemu-vde-HOWTO

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdeqemu $(DESTDIR)$(bindir)/vdekvm
	(cd $(DESTDIR)$(bindir) && $(LN_S) vdeq vdeqemu && $(LN_S) vdeq vdekvm )
	rm -f $(DESTDIR)$(bindir)/vdeo
	rm -f $(DESTDIR)$(bindir)/vdeoqemu

uninstall-local:
	rm -f $(bindir)/vdeqemu $(bindir)/vdekvm
