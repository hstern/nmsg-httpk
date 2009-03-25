CC = gcc
CFLAGS = -O2 -ggdb 
WARN = -Wall -Werror -Wno-strict-aliasing
INCLUDE = -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lev -lnmsg

BIN = nmsg-httpk nmsg-httpk-p0f
SRC = nmsg-httpk.c

all: $(BIN)

nmsg-httpk: $(SRC)
	$(CC) $(CFLAGS) $(WARN) -o $@ $(SRC) $(INCLUDE) $(LDFLAGS)

nmsg-httpk-p0f: nmsg-httpk.c
	$(CC) $(CFLAGS) $(WARN) -o $@ $(SRC) $(INCLUDE) $(LDFLAGS) -DUSE_P0F=1

clean:
	rm -f $(BIN)

.PHONY: all clean
