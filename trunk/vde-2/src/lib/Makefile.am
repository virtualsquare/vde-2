AM_CPPFLAGS = -I$(top_srcdir)/include \
              -DSYSCONFDIR="\"$(sysconfdir)\"" -DLOCALSTATEDIR="\"$(localstatedir)\""
LIBADD = $(top_builddir)/src/common/libvdecommon.la
SUBDIRS =

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

lib_LTLIBRARIES = \
	libvdesnmp.la \
	libvdemgmt.la \
	libvdeplug.la \
	libvdehist.la

# read before touching http://www.gnu.org/software/libtool/manual/libtool.html#Updating-version-info

libvdesnmp_la_LIBADD = $(LIBADD)
libvdesnmp_la_LDFLAGS = $(AM_LDFLAGS) -version-number 0:0:1 -export-dynamic

libvdemgmt_la_LIBADD = $(LIBADD)
libvdemgmt_la_LDFLAGS = $(AM_LDFLAGS) -version-number 0:0:1 -export-dynamic

libvdeplug_la_LIBADD = $(LIBADD)
libvdeplug_la_LDFLAGS = $(AM_LDFLAGS) -version-number 3:0:1 -export-dynamic

libvdehist_la_LIBADD = $(LIBADD)
libvdehist_la_LDFLAGS = $(AM_LDFLAGS) -version-number 0:0:1 -export-dynamic

if ENABLE_PYTHON
SUBDIRS += python
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vdesnmp.pc vdemgmt.pc vdeplug.pc vdehist.pc

