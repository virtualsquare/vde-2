AR = ar
RANLIB = ranlib
CC = gcc
LD = ld

BIN_DIR ?= /usr/local/bin
LIB_DIR ?= /usr/local/lib

all: vdetap libvdetap.so

libvdetap.so: libvdetap.a
	$(LD) -E -o $@ -L./ -ldl -shared -export-dynamic -Bdynamic \
	              --whole-archive libvdetap.a

libvdetap.a: libvdetap.o
	@rm -f $@
	@echo linking $@
	$(AR) ru $@ libvdetap.o && $(RANLIB) $@

libvdetap.o: libvdetap.c

vdetap: vdetap.o

vdetap.o: vdetap.c

clean:
	rm -f *.o *.a *.so vdetap

install:
	install -d $(BIN_DIR) 
	install -d $(LIB_DIR) 
	install -s vdetap $(BIN_DIR) 
	install libvdetap.so $(LIB_DIR)
