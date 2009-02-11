nmsg-httpk: nmsg-httpk.c
	$(CC) -O2 -ggdb -Wall -Werror -Wno-strict-aliasing -o nmsg-httpk nmsg-httpk.c -lev -lnmsg

clean:
	rm -f nmsg-httpk

.PHONY: clean
