AM_CPPFLAGS = -I$(top_srcdir)/include \
              -DSYSCONFDIR="\"$(sysconfdir)\"" -DLOCALSTATEDIR="\"$(localstatedir)\""
LIBADD = $(top_builddir)/src/common/libvdecommon.la

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

lib_LTLIBRARIES = libvdemgmt.la

# read before touching http://www.gnu.org/software/libtool/manual/libtool.html#Updating-version-info

libvdemgmt_la_LIBADD = $(LIBADD)
libvdemgmt_la_LDFLAGS = $(AM_LDFLAGS) -version-number 0:0:1 -export-dynamic

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vdemgmt.pc
