SUBDIRS = common include libvdeplug qemu slirpvde bochs uml doc dpipe wirefilter unixterm vde_switch vde_plug vde_plug2tap vde_over_ns vde_l3 libvdemgmt unixcmd vde_autolink libvdesnmp 
# kvde_switch


if CAN_MAKE_LIBVDETAP
  SUBDIRS += vdetaplib tunctl
endif

if ENABLE_CRYPTCAB
  SUBDIRS += vde_cryptcab
endif

if ENABLE_EXPERIMENTAL
  SUBDIRS += plugin
endif

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = LICENSE Changelog

extraclean: distclean
	rm -rf aclocal.m4 autom4te.cache autoscan.log configure.scan config.h.in* configure depcomp install-sh Makefile.in config.guess config.sub ltmain.sh missing `find . -name Makefile.in` vde-*.tar.gz
