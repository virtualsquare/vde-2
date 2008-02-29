AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libvdeplug
bin_PROGRAMS = vde_cryptcab
vde_cryptcab_SOURCES = vde_cryptcab.c crc32.c blowfish.c blowfish.h crc32.h
vde_cryptcab_LDADD = $(top_srcdir)/common/libvdecommon.la -lcrypto $(top_srcdir)/libvdeplug/libvdeplug.la
vde_cryptcab_LDFLAGS = -Wl,-ldl
