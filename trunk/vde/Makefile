TUNTAP = $(shell [ -e /usr/include/linux/if_tun.h ] && echo -DTUNTAP)

OBJSSW = hash.o port.o vde_switch.o tuntap.o
BINSW = vde_switch
BIN = $(BINSW) dpipe vde_plug
#CFLAGS = -g -Wall $(TUNTAP) -DINFO -O3
CFLAGS = -Wall $(TUNTAP) -O3

BIN_DIR ?= /usr/local/bin

ifneq ($(TUNTAP),)
	OBJS += tuntap.o
endif

all : $(BIN)

hash.o:	hash.c switch.h hash.h

port.o:	port.c switch.h hash.h port.h

tuntap.o: tuntap.c port.h

vde_plug.o:	vde_plug.c vde.h

vde_switch.o: vde_switch.c vde.h switch.h hash.h port.h tuntap.h

$(BINSW) : $(OBJSSW)
	$(CC) $(CFLAGS) -o $(BINSW) $(OBJSSW)

dpipe: dpipe.o 
	$(CC) $(CFLAGS) -o dpipe dpipe.o	
	
vde_plug: vde_plug.o
	$(CC) $(CFLAGS) -o vde_plug vde_plug.o

clean : 
	rm -f $(BIN) *.o *~ 

install : $(BIN)
	install -d $(DESTDIR)$(BIN_DIR)
	install -s $(BIN) $(DESTDIR)$(BIN_DIR)
