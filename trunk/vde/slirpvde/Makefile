OBJ= cksum.o debug.o if.o ip_icmp.o ip_input.o ip_output.o mbuf.o \
misc.o sbuf.o slirp.o socket.o tcp_input.o tcp_output.o tcp_subr.o \
tcp_timer.o udp.o \
bootp.o

CFLAGS=-I. -DVDE

all: libslirp.a slirpvde

libslirp.a: $(OBJ)
	ar ru libslirp.a $(OBJ)
	
bootp.o: bootp.c
cksum.o: cksum.c
debug.o: debug.c
if.o: if.c
ip_icmp.o: ip_icmp.c slirp.h config.h slirp_config.h debug.h ip.h tcp.h \
  tcp_var.h tcpip.h tcp_timer.h udp.h icmp_var.h mbuf.h sbuf.h socket.h \
  if.h main.h misc.h ctl.h bootp.h libslirp.h ip_icmp.h
ip_input.o: ip_input.c ip_icmp.h
ip_output.o: ip_output.c
mbuf.o: mbuf.c
misc.o: misc.c
sbuf.o: sbuf.c
slirp.o: slirp.c slirp.h config.h slirp_config.h debug.h ip.h tcp.h \
  tcp_var.h tcpip.h tcp_timer.h udp.h icmp_var.h mbuf.h sbuf.h socket.h \
  if.h main.h misc.h ctl.h bootp.h libslirp.h
slirpvde.o: slirpvde.c
socket.o: socket.c ip_icmp.h main.h
tcp_input.o: tcp_input.c ip_icmp.h
tcp_output.o: tcp_output.c
tcp_subr.o: tcp_subr.c
tcp_timer.o: tcp_timer.c
udp.o: udp.c ip_icmp.h

slirpvde: slirpvde.o libslirp.a
	$(CC) -o slirpvde slirpvde.o libslirp.a

clean:
	rm -rf *.o slirpvde libslirp.a

install : slirpvde
	install -d $(DESTDIR)$(BIN_DIR)
	install -s slirpvde $(DESTDIR)$(BIN_DIR)

