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
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <assert.h>
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
#include <nmsg/isc/pbnmsg_isc_http.h>

#define MODULE_DIR      "/usr/local/lib/nmsg"

#define DATA_TIMEOUT	2.0
#define BACKLOG		128

#define ACCF_HACK	1
#define SHUTDOWN_HACK	1
#define SOLINGER_HACK	1

#define struct_client_from(cli, field) \
	((struct client *) (((char *) cli) - offsetof(struct client, field)))

#if USE_P0F
# include "p0f-query.h"

static struct sockaddr_un p0f_sock;
static void query_p0f(struct p0f_response *, uint32_t, uint32_t,
		      uint16_t, uint16_t);
#endif

struct client {
	int fd;
	ev_io io;
	ev_timer timeout;
	struct sockaddr_in sock;
};

static struct ev_loop *loop;

static Nmsg__Isc__Http http;
static nmsg_buf buf;
static nmsg_pbmod mod;
static nmsg_pbmodset ms;
static void *clos;

static int setnonblock(int);
static void timeout_cb(struct ev_loop *, struct ev_timer *, int);
static void io_cb(struct ev_loop *, struct ev_io *, int);
static void accept_cb(struct ev_loop *, struct ev_io *, int);
static void shutdown_handler(int);

static int
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

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *w, int revents) {
	struct client *cli = struct_client_from(w, timeout);
	ev_io_stop(EV_A_ &cli->io);
	close(cli->fd);
	free(cli);
}

static void
io_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
	struct client *cli = struct_client_from(w, io);
	static char response[] = "HTTP/1.1 404 Not Found\r\n";
	static char rbuf[1024];
	int r = 0;
	uint32_t srcip, dstip;

	struct timespec ts;
	Nmsg__NmsgPayload *np;
	nmsg_res res;

	struct sockaddr_in http_sock;
	socklen_t http_sock_len;

#if USE_P0F
	struct p0f_response p;
#endif

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

		http_sock_len = sizeof(http_sock);
		if (getsockname(cli->fd, (struct sockaddr *) &http_sock,
				&http_sock_len) != 0)
		{
			perror("getsockname");
			return;
		}

		srcip = cli->sock.sin_addr.s_addr;
		dstip = http_sock.sin_addr.s_addr;

		http.srcip.data = (uint8_t *) &srcip;
		http.srcip.len = 4;
		http.has_srcip = true;

		http.srcport = ntohs(cli->sock.sin_port);
		http.has_srcport = true;

		http.dstip.data = (uint8_t *) &dstip;
		http.dstip.len = 4;
		http.has_dstip = true;

		http.dstport = ntohs(http_sock.sin_port);
		http.has_dstport = true;

		http.request.data = (uint8_t *) rbuf;
		http.request.len = r + 1;
		http.has_request = true;

#if USE_P0F
		memset(&p, 0, sizeof(p));
		query_p0f(&p, srcip, dstip, http.srcport, http.dstport);
		if (p.type == P0F_RESP_OK) {
			if (p.genre[0] != '\0') {
				http.p0f_genre.data = p.genre;
				http.p0f_genre.len = strlen((char *) p.genre) + 1;
				http.has_p0f_genre = true;
			}
			if (p.detail[0] != '\0') {
				http.p0f_detail.data = p.detail;
				http.p0f_detail.len = strlen((char *) p.detail) + 1;
				http.has_p0f_detail = true;
			}
			if (p.link[0] != '\0') {
				http.p0f_link.data = p.link;
				http.p0f_link.len = strlen((char *) p.link) + 1;
				http.has_p0f_link = true;
			}
			if (p.tos[0] != '\0') {
				http.p0f_tos.data = p.tos;
				http.p0f_tos.len = strlen((char *) p.tos) + 1;
				http.has_p0f_tos = true;
			}

			if (p.dist != 0) {
				http.p0f_dist = p.dist;
				http.has_p0f_dist = true;
			}

			if (p.fw != 0) {
				http.p0f_fw = p.fw;
				http.has_p0f_fw = true;
			}

			if (p.nat != 0) {
				http.p0f_nat = p.nat;
				http.has_p0f_nat = true;
			}

			if (p.real != 0) {
				http.p0f_real = p.real;
				http.has_p0f_real = true;
			}

			if (p.score != 0) {
				http.p0f_score = p.score;
				http.has_p0f_score = true;
			}

			if (p.mflags != 0) {
				http.p0f_mflags = p.mflags;
				http.has_p0f_mflags = true;
			}

			http.p0f_uptime = p.uptime;
			http.has_p0f_uptime = true;
		}
#endif

		nmsg_time_get(&ts);
		np = nmsg_payload_from_message(&http, NMSG_VENDOR_ISC_ID,
					       MSGTYPE_HTTP_ID, &ts);
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

static void
accept_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
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

static void
shutdown_handler(int signum) {
	ev_unloop(loop, EVUNLOOP_ALL);
	nmsg_pbmod_fini(mod, &clos);
	nmsg_output_close(&buf);
	nmsg_pbmodset_destroy(&ms);
	exit(0);
}

#if USE_P0F
static void
query_p0f(struct p0f_response *r,
	  uint32_t srcip, uint32_t dstip,
	  uint16_t srcport, uint16_t dstport)
{
	int fd;
	struct p0f_query q = {
		.magic		= P0F_QUERY_MAGIC,
		.id		= 0xdeadbeef,
		.type		= P0F_QTYPE_FP,
		.src_ip		= srcip,
		.dst_ip		= dstip,
		.src_port	= srcport,
		.dst_port	= dstport
	};

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "p0f socket failed");
	if (connect(fd, (struct sockaddr *) &p0f_sock, sizeof(p0f_sock)))
		err(1, "p0f connect failed");

	if (write(fd, &q, sizeof(q)) != sizeof(q))
		err(1, "p0f socket write error");
	if (read(fd, r, sizeof(*r)) != sizeof(*r))
		err(1, "p0f socket read error");
	if (r->magic != P0F_QUERY_MAGIC)
		err(1, "bad p0f response magic");
	if (r->type == P0F_RESP_BADQUERY)
		err(1, "p0f did not honor our query");

	close(fd);
}
#endif

int
main(int argc, char **argv) {
#if USE_P0F
	const char *p0f_path;
#endif
	const char *http_addr, *http_port, *nmsg_addr, *nmsg_port;
	ev_io ev_accept;
	int http_fd, nmsg_fd;
	nmsg_res res;
	static int reuseaddr_on = 1;
	struct sockaddr_in http_sock, nmsg_sock;

	/* setup signal handlers */
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, shutdown_handler);
	signal(SIGTERM, shutdown_handler);

#if USE_P0F
	if (argc != 6) {
		fprintf(stderr, "usage: %s <HTTPaddr> <HTTPport> <NMSGaddr> <NMSGport> <P0Fsock>\n", argv[0]);
		return (1);
	}
	p0f_path = argv[5];

	/* p0f sockaddr */
	p0f_sock.sun_family = AF_UNIX;
	strncpy(p0f_sock.sun_path, p0f_path, sizeof(p0f_sock.sun_path));
#else
	if (argc != 5) {
		fprintf(stderr, "usage: %s <HTTPaddr> <HTTPport> <NMSGaddr> <NMSGport>\n", argv[0]);
		return (1);
	}
#endif
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
	mod = nmsg_pbmodset_lookup(ms, NMSG_VENDOR_ISC_ID, MSGTYPE_HTTP_ID);
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
