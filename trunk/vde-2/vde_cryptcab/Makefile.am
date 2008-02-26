bin_PROGRAMS = vde_cryptcab
vde_cryptcab_SOURCES = vde_cryptcab.c crc32.c blowfish.c blowfish.h crc32.h
vde_cryptcab_LDADD = ../compat/libvdecompat.la -lcrypto ../libvdeplug/libvdeplug.la
vde_cryptcab_LDFLAGS = -Wl,-ldl
