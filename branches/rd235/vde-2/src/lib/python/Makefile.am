moddir = $(pythondir)

AM_LIBTOOLFLAGS = --tag=disable-static

LIBADD = $(top_builddir)/src/lib/libvdeplug/libvdeplug.so

mod_LTLIBRARIES = vdeplug_python.la
dist_python_SCRIPTS = VdePlug.py

vdeplug_python_la_CFLAGS = -I$(top_srcdir)/include $(PYTHON_CFLAGS) $(PYTHON_INCLUDES)
vdeplug_python_la_LIBADD = $(PYTHON_LIBS) $(top_builddir)/src/lib/libvdeplug/libvdeplug.la
vdeplug_python_la_LDFLAGS = -module -avoid-version
