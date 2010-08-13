PYTHONINCLUDEDIR=`python -c "from distutils.sysconfig import get_python_inc; print get_python_inc();"`
PYTHONLIBDIR=`python -c "from distutils.sysconfig import get_python_lib; print get_python_lib();"`



all: vdeplug_python.so

vdeplug_python.o: vdeplug_python.c
	gcc -c vdeplug_python.c -I /usr/include/python2.5

vdeplug_python.so: vdeplug_python.o
	gcc -shared vdeplug_python.o /usr/lib/libvdeplug.so -o vdeplug_python.so

distclean: clean

clean:
	rm -f *.so *.o *.pyc

install:
	install vdeplug_python.so $(PYTHONLIBDIR)
	@echo INCLUDES are in $(PYTHONINCLUDEDIR)
	@echo LIBS are in $(PYTHONLIBDIR)
	install VdePlug.py $(PYTHONLIBDIR)

uninstall:
	rm -f  $(PREFIX)/lib/vdeplug_python.so
	rm -f $(PYTHONLIBDIR)/VdePlug.py
