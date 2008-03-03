AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)

bin_PROGRAMS = vdeq
vdeq_SOURCES = vdeq.c
vdeq_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdeplug/libvdeplug.la
#vdeq_LDFLAGS = -Wl,-ldl

EXTRA_DIST = README qemu-vde-HOWTO

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdeqemu $(DESTDIR)$(bindir)/vdekvm
	(cd $(DESTDIR)$(bindir) && $(LN_S) vdeq vdeqemu && $(LN_S) vdeq vdekvm )
	rm -f $(DESTDIR)$(bindir)/vdeo
	rm -f $(DESTDIR)$(bindir)/vdeoqemu

uninstall-local:
	rm -f $(bindir)/vdeqemu $(bindir)/vdekvm
