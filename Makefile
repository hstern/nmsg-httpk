lighttz-nmsg: lighttz-nmsg.c
	$(CC) -O3 -Wall -Wno-strict-aliasing -o lighttz-nmsg lighttz-nmsg.c -lev -lnmsg

clean:
	rm -f lighttz-nmsg

.PHONY: clean
