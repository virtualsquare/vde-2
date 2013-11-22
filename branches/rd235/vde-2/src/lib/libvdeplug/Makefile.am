AM_CPPFLAGS = -I$(top_srcdir)/include \
              -DSYSCONFDIR="\"$(sysconfdir)\"" -DLOCALSTATEDIR="\"$(localstatedir)\""
LIBADD = $(top_builddir)/src/common/libvdecommon.la
SUBDIRS =

if ENABLE_PROFILE
  AM_CFLAGS = -pg --coverage
  AM_LDFLAGS = -pg --coverage
endif

lib_LTLIBRARIES = libvdeplug.la 

# read before touching http://www.gnu.org/software/libtool/manual/libtool.html#Updating-version-info

libvdeplug_la_SOURCES =  \
	libvdeplug.c \
	libvdeplug_ptp.c \
	libvdeplug_vde.c \
	libvdeplug_kvde.c \
	libvdeplug_udp.c \
	libvdestream.c

libvdeplug_la_LIBADD = $(LIBADD)
libvdeplug_la_LDFLAGS = $(AM_LDFLAGS) -version-number 3:0:2 -export-dynamic

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = vdeplug.pc
