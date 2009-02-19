/*
 * Copyright (c) 2009 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
#include <assert.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>

#include <nmsg.h>
#include <nmsg/output.h>
#include <nmsg/payload.h>
#include <nmsg/pbmod.h>
#include <nmsg/pbmodset.h>
#include <nmsg/time.h>
#include <nmsg/isc/http.pb-c.h>

#define MODULE_DIR      "/usr/local/lib/nmsg"
#define MODULE_VENDOR   "ISC"
#define MODULE_MSGTYPE  "http"

#define DATA_TIMEOUT	2.0
#define BACKLOG		128

#define ACCF_HACK	1
#define SHUTDOWN_HACK	1
#define SOLINGER_HACK	1

#define struct_client_from(cli, field) \
	((struct client *) (((char *) cli) - offsetof(struct client, field)))

static struct ev_loop *loop;

struct client {
	int fd;
	ev_io io;
	ev_timer timeout;
	struct sockaddr_in sock;
};
struct sockaddr_in http_sock;

static Nmsg__Isc__Http http;
static nmsg_buf buf;
static nmsg_pbmod mod;
static nmsg_pbmodset ms;
static unsigned vid, msgtype;
static void *clos;

int
setnonblock(int fd) {
	int flags;
	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return (flags);
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return (-1);
	return (0);
}

static
void timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
	struct client *cli = struct_client_from(w, timeout);
	ev_io_stop(EV_A_ &cli->io);
	close(cli->fd);
	free(cli);
}

static
void io_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct client *cli = struct_client_from(w, io);
	static char response[] = "HTTP/1.1 404 Not Found\r\n";
	static char rbuf[1024];
	int r = 0;

	struct timespec ts;
	Nmsg__NmsgPayload *np;

	if (revents & EV_READ) {
		r = read(cli->fd, &rbuf, sizeof(rbuf) - 1);
		rbuf[r] = 0;
#if SHUTDOWN_HACK
		shutdown(cli->fd, SHUT_RD); /* vixie hack */
#endif
		memset(&http, 0, sizeof(http));
		res = nmsg_pbmod_message_init(mod, &http);
		if (res != nmsg_res_success)
			err(1, "unable to initialize http message");
		http.type = NMSG__ISC__HTTP_TYPE__sinkhole;

		ev_io_stop(loop, w);
		ev_io_init(&cli->io, io_cb, cli->fd, EV_WRITE);
		ev_io_start(loop, w);

		http.srcip.data = (uint8_t *) &cli->sock.sin_addr.s_addr;
		http.srcip.len = 4;
		http.has_srcip = true;

		http.srcport = htons(cli->sock.sin_port);
		http.has_srcport = true;

		http.dstip.data = (uint8_t *) &http_sock.sin_addr.s_addr;
		http.dstip.len = 4;
		http.has_dstip = true;

		http.dstport = htons(http_sock.sin_port);
		http.has_dstport = true;

		http.request.data = (uint8_t *) rbuf;
		http.request.len = r + 1;
		http.has_request = true;

		nmsg_time_get(&ts);
		np = nmsg_payload_from_message(&http, vid, msgtype, &ts);
		assert(np != NULL);
		nmsg_output_append(buf, np);
	} else if (revents & EV_WRITE) {
		write(cli->fd, response, sizeof(response) - 1);
		ev_io_stop(EV_A_ w);
		close(cli->fd);
		ev_timer_stop(EV_A_ &cli->timeout);
		free(cli);
	}
}

static
void accept_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
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

	/* linger hack */
#if SOLINGER_HACK
	struct linger linger = { .l_onoff = 1, .l_linger = 0 };
	setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
#endif

	ev_io_init(&client->io, io_cb, client->fd, EV_READ);
	ev_timer_init(&client->timeout, timeout_cb, DATA_TIMEOUT, 0.);
	ev_timer_start(loop, &client->timeout);
	ev_io_start(loop, &client->io);
}

static
void shutdown_handler(int signum) {
	ev_unloop(loop, EVUNLOOP_ALL);
	nmsg_pbmod_fini(mod, &clos);
	nmsg_output_close(&buf);
	nmsg_pbmodset_destroy(&ms);
	exit(0);
}

int
main(int argc, char **argv) {
	const char *http_addr, *http_port, *nmsg_addr, *nmsg_port;
	ev_io ev_accept;
	int http_fd, nmsg_fd;
	nmsg_res res;
	static int reuseaddr_on = 1;
	struct sockaddr_in nmsg_sock;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, shutdown_handler);
	signal(SIGTERM, shutdown_handler);
	if (argc != 5)
		err(1, "usage: %s <HTTPaddr> <HTTPport> <NMSGaddr> <NMSGport>", argv[0]);
	http_addr = argv[1];
	http_port = argv[2];
	nmsg_addr = argv[3];
	nmsg_port = argv[4];

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
	if (connect(nmsg_fd, (struct sockaddr *) &nmsg_sock,
		    sizeof(struct sockaddr_in)) < 0)
	{
		err(1, "connect failed");
	}

	/* nmsg output buf */
	buf = nmsg_output_open_sock(nmsg_fd, 8000);
	if (buf == NULL)
		err(1, "unable to nmsg_output_open_sock()");

	/* nmsg modules */
	ms = nmsg_pbmodset_init(MODULE_DIR, 0);
	if (ms == NULL)
		err(1, "unable to nmsg_pbmodset_init()");

	/* http pbnmsg module */
	vid = nmsg_pbmodset_vname_to_vid(ms, MODULE_VENDOR);
	msgtype = nmsg_pbmodset_mname_to_msgtype(ms, vid, MODULE_MSGTYPE);
	mod = nmsg_pbmodset_lookup(ms, vid, msgtype);
	if (mod == NULL)
		err(1, "unable to acquire module handle");
	res = nmsg_pbmod_init(mod, &clos, 0);
	if (res != nmsg_res_success)
		err(1, "unable to initialize module");

	/* initialize our message */
	res = nmsg_pbmod_message_init(mod, &http);
	if (res != nmsg_res_success)
		err(1, "unable to initialize http message");
	http.type = NMSG__ISC__HTTP_TYPE__sinkhole;

	/* http socket */
	if (inet_pton(AF_INET, http_addr, &http_sock.sin_addr)) {
		http_sock.sin_family = AF_INET;
		http_sock.sin_port = htons(atoi(http_port));
	} else {
		err(1, "http_addr inet_pton failed");
	}
	http_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (http_fd < 0)
		err(1, "listen failed");
	if (setsockopt(http_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on,
		sizeof(reuseaddr_on)) == -1)
	{
		err(1, "setsockopt failed");
	}

#if __FreeBSD__ && ACCF_HACK
	/* freebsd accf_http(9) hack */
	struct accept_filter_arg afa;
	bzero(&afa, sizeof(afa));
	strcpy(afa.af_name, "httpready");
	setsockopt(http_fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa));
#endif

	if (bind(http_fd, (struct sockaddr *) &http_sock,
		sizeof(http_sock)) < 0)
	{
		err(1, "bind failed");
	}
	if (listen(http_fd, BACKLOG) < 0)
		err(1, "listen failed");
	if (setnonblock(http_fd) < 0)
		err(1, "failed to set server socket non-blocking");

	/* libev loop */
	loop = ev_default_loop(0);
	ev_io_init(&ev_accept, accept_cb, http_fd, EV_READ);
	ev_io_start(loop, &ev_accept);
	ev_loop(loop, 0);

	return (0);
}
