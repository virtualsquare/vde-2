moddir = $(pythondir)

AM_LIBTOOLFLAGS = --tag=disable-static

LIBADD = $(top_builddir)/src/lib/libvdeplug.so 

mod_LTLIBRARIES = vdeplug_python.la
dist_python_SCRIPTS = VdePlug.py 

vdeplug_python_la_CFLAGS = $(PYTHON_CFLAGS) -I$(PYTHONINCLUDEDIR)
vdeplug_python_la_LIBADD = $(PYTHON_LIBS)
vdeplug_python_la_LDFLAGS = -module -avoid-version
