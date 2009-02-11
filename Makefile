CFLAGS = -O2 -ggdb 
WARN = -Wall -Werror -Wno-strict-aliasing
INCLUDE = -I/usr/local/include
LDFLAGS = -L/usr/local/lib -lev -lnmsg

nmsg-httpk: nmsg-httpk.c
	$(CC) $(CFLAGS) $(WARN) -o $@ $< $(INCLUDE) $(LDFLAGS)

clean:
	rm -f nmsg-httpk

.PHONY: clean
