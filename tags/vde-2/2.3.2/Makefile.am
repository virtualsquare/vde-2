SUBDIRS = include src man doc
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = Changelog COPYING COPYING.libvdeplug COPYING.slirpvde INSTALL README

DISTCHECK_CONFIGURE_FLAGS = --enable-experimental

extraclean: distclean
	rm -f \
	aclocal.m4 \
	autom4te.cache \
	autoscan.log \
	configure.scan \
	configure \
	depcomp \
	install-sh \
	Makefile.in \
	config.guess \
	config.sub \
	ltmain.sh \
	missing \
	compile \
	include/config.h.in* \
	vde2-*.tar.gz \
	vde2-*.tar.bz2 \
	`find . -name Makefile.in` \
	$(cksum_file)

# release stuff
# https://sourceforge.net/apps/trac/sourceforge/wiki/Release%20files%20for%20download

cksum_file=$(distdir).checksum
trunk_url=https://vde.svn.sourceforge.net/svnroot/vde/trunk/vde-2
tag_url=https://vde.svn.sourceforge.net/svnroot/vde/tags/vde-2/$(PACKAGE_VERSION)

release_checksums: dist
	rm -f $(cksum_file)
	which sha1sum >/dev/null && sha1sum $(DIST_ARCHIVES) >> $(cksum_file)
	which sha256sum >/dev/null && sha256sum $(DIST_ARCHIVES) >> $(cksum_file)
# error if the file is empty (or non existant)
	/usr/bin/test -s $(cksum_file) || exit 1

release_steps:
	@/usr/bin/test -f release_ready || { \
	  echo "File release_ready not found, complete these steps first:"; \
	  echo "- check any outstanding bug on sf.net"; \
	  echo "- check any outstanding bug on bugs.debian.org"; \
	  echo "- update the changelog"; \
	  echo "- increase version number in configure.ac"; \
	  echo "Once you're done you can 'touch release_ready' to proceed"; exit 1; }

release_tag:
# check if release tag exists, othewise tag the release
	svn ls $(tag_url) 1>/dev/null || svn copy -m "Tag release $(PACKAGE_VERSION)" $(trunk_url) $(tag_url)

release: release_steps release_tag release_checksums
	reldir=`mktemp -d -t vde.XXXXXX`/$(PACKAGE_VERSION); \
	mkdir -p $$reldir; \
	cp -v $(DIST_ARCHIVES) $(cksum_file) $$reldir; \
	rm -f release_ready
	echo "***"
	echo "*** release ready at $$reldir, manual steps left:"; \
	echo "***"
	echo "gpg -o $$reldir/$(cksum_file).asc --clearsign $$reldir/$(cksum_file)"; \
	echo "rsync -e ssh -vaz $$reldir <SF_USERNAME>,vde@frs.sourceforge.net:/home/frs/project/v/vd/vde/vde2/"
