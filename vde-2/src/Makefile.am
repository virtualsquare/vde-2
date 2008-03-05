AM_CPPFLAGS = -I$(top_srcdir)/include

bin_PROGRAMS = \
dpipe
unixcmd
unixterm
vde_autolink
vde_plug2tap
vde_plug
vdeq
vde_tunctl
wirefilter

#########

# dpipe_SOURCES = dpipe.c
# wirefilter_SOURCES = wirefilter.c

wirefilter_LDADD = lib/common/libvdecommon.la lib/
#wirefilter_LDFLAGS = -Wl,-ldl
bin_PROGRAMS = vde_plug2tap

vde_plug2tap_SOURCES = vde_plug2tap.c 
vde_plug2tap_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdeplug/libvdeplug.la
#vde_plug2tap_LDFLAGS = -Wl,-ldl
bin_PROGRAMS = vde_plug

vde_plug_SOURCES = vde_plug.c 
vde_plug_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdeplug/libvdeplug.la
#vde_plug_LDFLAGS = -Wl,-ldl
bin_PROGRAMS = vde_autolink
vde_autolink_SOURCES = vde_autolink.c
vde_autolink_LDADD = $(top_srcdir)/common/libvdecommon.la $(top_srcdir)/libvdemgmt/libvdemgmt.la
#vde_autolink_LDFLAGS = -Wl,-ldl

bin_PROGRAMS = unixterm
unixterm_SOURCES = unixterm.c
unixterm_LDADD = $(top_srcdir)/common/libvdecommon.la
#unixterm_LDFLAGS = -Wl,-ldl
bin_PROGRAMS = unixcmd
unixcmd_SOURCES = unixcmd.c
unixcmd_LDADD = $(top_srcdir)/common/libvdecommon.la
#unixcmd_LDFLAGS = -Wl,-ldl

install-exec-hook:
	rm -f $(DESTDIR)$(bindir)/vdecmd
	(cd $(DESTDIR)$(bindir) && $(LN_S) unixcmd vdecmd)

uninstall-local:
	rm -f $(bindir)/vdecmd
EXTRA_DIST = README
sbin_PROGRAMS = vde_tunctl
vde_tunctl_SOURCES = vde_tunctl.c

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

lib_LTLIBRARIES = libvdesnmp.la

libvdesnmp_la_SOURCES = libvdesnmp.c
libvdesnmp_la_LDFLAGS = -version-number 0:0:1 -export-dynamic

libvdesnmp_la_CFLAGS = -I$(top_srcdir)/libvdemgmt/ -I$(top_srcdir)/plugin/

libvdesnmp_la_LIBADD = $(top_srcdir)/common/libvdecommon.la

include_HEADERS = libvdesnmp.h
lib_LTLIBRARIES = libvdemgmt.la

libvdemgmt_la_SOURCES = libvdemgmt.c
libvdemgmt_la_LDFLAGS = -version-number 0:0:1 -export-dynamic

libvdemgmt_la_LIBADD = $(top_srcdir)/common/libvdecommon.la

include_HEADERS = libvdemgmt.h


lib_LTLIBRARIES = libvdeplug.la

libvdeplug_la_SOURCES = libvdeplug.c
libvdeplug_la_LDFLAGS = -version-number 2:1 -export-dynamic

nobase_include_HEADERS = libvdeplug.h libvdeplug_dyn.h
