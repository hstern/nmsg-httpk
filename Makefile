sie-nmsg-httpk: sie-nmsg-httpk.c
	$(CC) -O2 -ggdb -Wall -Werror -Wno-strict-aliasing -o sie-nmsg-httpk sie-nmsg-httpk.c -lev -lnmsg

clean:
	rm -f sie-nmsg-httpk

.PHONY: clean
