/* nmsg version */

/*
Copyright (c) 2008, Arek Bochinski
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice, 
	* this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice, 
	* this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
	* Neither the name of Arek Bochinski nor the names of its contributors may be used to endorse or 
	* promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Compile command on my system, may be changed depending on your setup.

gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"lighttz.d" -MT"lighttz.d" -o"lighttz.o" "../lighttz.c"
gcc  -o"lighttz"  ./lighttz.o   -lev

You need to have Libev installed:
http://software.schmorp.de/pkg/libev.html
*/


#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h> 
#include <unistd.h>

#include <ev.h>

#include <nmsg.h>
#include <nmsg/output.h>
#include <nmsg/payload.h>
#include <nmsg/pbmod.h>
#include <nmsg/pbmodset.h>
#include <nmsg/time.h>

#define MODULE_DIR      "/usr/local/lib/nmsg"
#define MODULE_VENDOR   "ISC"
#define MODULE_MSGTYPE  "http"

struct client {
	int fd;
	ev_io io;
	ev_timer ev_timeout;
	struct sockaddr_in sock;
};

static ev_io ev_accept;

static nmsg_buf buf;
static nmsg_pbmod mod;
static nmsg_pbmodset ms;
static unsigned vid, msgtype;
static void *clos;

int setnonblock(int fd) {
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return (flags);
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) 
		return (-1);

	return (0);
}

static void timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
	struct client *cli = ((struct client*) (((char*)w) - offsetof(struct client,ev_timeout)));
	ev_io_stop(EV_A_ &cli->io);
	//ev_timer_stop(EV_A_ &cli->ev_timeout);
	close(cli->fd);
	free(cli);
}

static void io_cb(struct ev_loop *loop, struct ev_io *w, int revents) { 
	struct client *cli = ((struct client*) (((char*)w) - offsetof(struct client,io)));
	static char response[] = "HTTP/1.1 404 Not Found\r\n";
	static char rbuf[1024];
	int r = 0;
	uint16_t srcport;

	nmsg_res res;
	uint8_t *pbuf;
	size_t sz;
	struct timespec ts;
	Nmsg__NmsgPayload *np;

	if (revents & EV_READ) {
		r = read(cli->fd, &rbuf, sizeof(rbuf) - 1);
		rbuf[r] = 0;
		ev_io_stop(loop, w);
		ev_io_init(&cli->io, io_cb, cli->fd, EV_WRITE);
		ev_io_start(loop, w);

		nmsg_pbmod_field2pbuf(mod, clos, "type", (const u_char *) "sinkhole", sizeof("sinkhole"), NULL, NULL);
		nmsg_pbmod_field2pbuf(mod, clos, "srcip", (const u_char *) &cli->sock.sin_addr.s_addr, 4, NULL, NULL);
		srcport = htons(cli->sock.sin_port);
		nmsg_pbmod_field2pbuf(mod, clos, "srcport", (const u_char *) &srcport, sizeof(srcport), NULL, NULL);
		nmsg_pbmod_field2pbuf(mod, clos, "request", (const u_char *) rbuf, r + 1, NULL, NULL);

		res = nmsg_pbmod_field2pbuf(mod, clos, NULL, NULL, 0, &pbuf, &sz);
		assert (res == nmsg_res_pbuf_ready);
		nmsg_time_get(&ts);
		np = nmsg_payload_make(pbuf, sz, vid, msgtype, &ts);
		assert(np != NULL);
		nmsg_output_append(buf, np);
	} else if (revents & EV_WRITE) {
		write(cli->fd, response, sizeof(response) - 1);
		ev_io_stop(EV_A_ w);
		close(cli->fd);
		ev_timer_stop(EV_A_ &cli->ev_timeout);
		free(cli);
	}
}

static void accept_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
	int client_fd;
	struct client *client;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);

	client_fd = accept(w->fd, (struct sockaddr *) &client_addr, &client_len);
	if (client_fd == -1)
		return;
	client = calloc(1, sizeof(*client));
	client->fd = client_fd;
	client->sock = client_addr;
	if (setnonblock(client->fd) < 0)
		err(1, "failed to set client socket to non-blocking");
	ev_io_init(&client->io, io_cb, client->fd, EV_READ);
	ev_timer_init(&client->ev_timeout, timeout_cb, 1.0, 0.);
	ev_timer_start(loop, &client->ev_timeout);
	ev_io_start(loop, &client->io);
}

int main(int argc, char **argv) {
	int listen_fd, nmsg_fd;
	static int reuseaddr_on = 1;
	struct ev_loop *loop;
	struct sockaddr_in listen_sock, nmsg_sock; 
	char *http_port, *nmsg_addr, *nmsg_port;

	signal(SIGPIPE, SIG_IGN);

	if (argc != 4)
		err(1, "usage: %s <HTTPport> <NMSGaddr> <NMSGport>", argv[0]);
	http_port = argv[1];
	nmsg_addr = argv[2];
	nmsg_port = argv[3];

	/* nmsg socket */
	if (inet_pton(AF_INET, nmsg_addr, &nmsg_sock.sin_addr)) {
		nmsg_sock.sin_family = AF_INET;
		nmsg_sock.sin_port = htons(atoi(nmsg_port));
	} else {
		err(1, "inet_pton failed");
	}
	nmsg_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (nmsg_fd < 0)
		err(1, "socket failed");
	if (connect(nmsg_fd, (struct sockaddr *) &nmsg_sock, sizeof(struct sockaddr_in)) < 0)
		err(1, "connect failed");

	/* nmsg output buf */
	buf = nmsg_output_open_sock(nmsg_fd, 8000);
	if (buf == NULL)
		err(1, "unable to nmsg_output_open_sock()");

	/* nmsg modules */
	ms = nmsg_pbmodset_init(MODULE_DIR, 0);
	if (ms == NULL)
		err(1, "unable to nmsg_pbmodset_init()");

	/* http pbnmsg module */
	vid = nmsg_pbmodset_vname2vid(ms, MODULE_VENDOR);
	msgtype = nmsg_pbmodset_mname2msgtype(ms, vid, MODULE_MSGTYPE);
	mod = nmsg_pbmodset_lookup(ms, vid, msgtype);
	if (mod == NULL)
		err(1, "unable to acquire module handle");
	clos = nmsg_pbmod_init(mod, 0);

	/* http socket */
	listen_fd = socket(AF_INET, SOCK_STREAM, 0); 
	if (listen_fd < 0)
		err(1, "listen failed");
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on,
		sizeof(reuseaddr_on)) == -1)
	{
		err(1, "setsockopt failed");
	}
	memset(&listen_sock, 0, sizeof(listen_sock));
	listen_sock.sin_family = AF_INET;
	listen_sock.sin_addr.s_addr = INADDR_ANY;
	listen_sock.sin_port = htons(atoi(http_port));
	if (bind(listen_fd, (struct sockaddr *) &listen_sock,
		sizeof(listen_sock)) < 0)
	{
		err(1, "bind failed");
	}
	if (listen(listen_fd, 128) < 0)
		err(1, "listen failed");
	if (setnonblock(listen_fd) < 0)
		err(1, "failed to set server socket to non-blocking");

	/* libev loop */
	loop = ev_default_loop(0);
	ev_io_init(&ev_accept, accept_cb, listen_fd, EV_READ);
	ev_io_start(loop, &ev_accept);
	ev_loop(loop, 0);

	/* nmsg close */
	nmsg_output_close(&buf);

	return (0);
}
