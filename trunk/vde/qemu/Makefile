BIN_DIR ?= /usr/local/bin

ALL: vdeq

vdeq.o: vdeq.c ../vde.h

vdeq: vdeq.o
	$(CC) -o vdeq vdeq.o

install : vdeq
	install -d $(DESTDIR)$(BIN_DIR)
	install -s vdeq $(DESTDIR)$(BIN_DIR)
	ln -s $(DESTDIR)$(BIN_DIR)/vdeq $(DESTDIR)$(BIN_DIR)/vdeqemu

clean:
	rm *.o
