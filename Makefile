CC = gcc
CFLAGS = -O2 -ggdb -fstack-protector --param=ssp-buffer-size=4
WARN = -Wall -Werror -Wno-strict-aliasing -Wformat -Werror=format-security
INCLUDE = 
LDFLAGS = -Wl,-z,relro -lev -lnmsg
DESTDIR = /usr/local

BIN = nmsg-httpk nmsg-httpk-p0f
SRC = nmsg-httpk.c

all: $(BIN)

nmsg-httpk: $(SRC)
	$(CC) $(CFLAGS) $(WARN) -o $@ $(SRC) $(INCLUDE) $(LDFLAGS)

nmsg-httpk-p0f: nmsg-httpk.c
	$(CC) $(CFLAGS) $(WARN) -o $@ $(SRC) $(INCLUDE) $(LDFLAGS) -DUSE_P0F=1

clean:
	rm -f $(BIN)

install:
	mkdir -p $(DESTDIR)/bin
	install -m 0755 $(BIN) $(DESTDIR)/bin

.PHONY: all clean install
