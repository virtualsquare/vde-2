ALL: vdeq

vdeq.o: vdeq.c ../vde.h

vdeq: vdeq.o
	$(CC) -o vdeq vdeq.o

install : vdeq
	install -d $(DESTDIR)$(BIN_DIR)
	install -s vdeq $(DESTDIR)$(BIN_DIR)
	rm -f $(DESTDIR)$(BIN_DIR)/vdeqemu
	ln -s $(DESTDIR)$(BIN_DIR)/vdeq $(DESTDIR)$(BIN_DIR)/vdeqemu

clean:
	rm -f *.o
