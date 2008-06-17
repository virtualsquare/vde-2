AM_CPPFLAGS = -I$(top_srcdir)/include
bin_PROGRAMS = vde_cryptcab
vde_cryptcab_SOURCES = crc32.c crc32.h cryptcab.h cryptcab.c vde_cryptcab_server.c vde_cryptcab_client.c
vde_cryptcab_LDADD = $(top_srcdir)/src/common/libvdecommon.la -lcrypto $(top_srcdir)/src/lib/libvdeplug.la
