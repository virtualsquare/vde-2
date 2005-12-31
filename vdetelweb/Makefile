LOADLIBES=-ldl -lpthread
BINDIR=/usr/local/bin
MANDIR=/usr/local/man

all: vdetelweb

vdetelweb: vdetelweb.o web.o telnet.o

install:
	install vdetelweb $(BINDIR)
	install vdetelweb.1 $(MANDIR)/man1

clean:
	rm -rf *.o
