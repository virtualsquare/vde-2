LOADLIBES=/usr/local/lib/liblwip.so -lpthread
BINDIR=/usr/local/bin

all: vdetelweb

vdetelweb: vdetelweb.o web.o telnet.o

install:
	install vdetelweb $(BINDIR)

clean:
	rm -rf *.o
