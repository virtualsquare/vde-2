AM_CPPFLAGS = -I$(top_srcdir)/include
bin_PROGRAMS = vde_cryptcab
vde_cryptcab_SOURCES = vde_cryptcab.c crc32.c blowfish.c blowfish.h crc32.h
vde_cryptcab_LDADD = $(top_srcdir)/src/common/libvdecommon.la -lcrypto $(top_srcdir)/src/lib/libvdeplug.la
