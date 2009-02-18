CFLAGS = -O2 -ggdb 
WARN = -Wall -Werror -Wno-strict-aliasing
INCLUDE = -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lev -lnmsg

BIN = nmsg-httpk nmsg-httpk-p0f

all: $(BIN)

nmsg-httpk: nmsg-httpk.c
	$(CC) $(CFLAGS) $(WARN) -o $@ $< $(INCLUDE) $(LDFLAGS)

nmsg-httpk-p0f: nmsg-httpk-p0f.c
	$(CC) $(CFLAGS) $(WARN) -o $@ $< $(INCLUDE) $(LDFLAGS)

clean:
	rm -f $(BIN)

.PHONY: all clean
