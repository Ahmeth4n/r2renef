/* r2renef - MIT - Copyright 2025-2026 */

#include "renef_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define RN_ASYNC_MAX (256 * 1024)  /* unsolicited output kept per connection */
#define RN_LEGACY_GRACE_MS 80      /* legacy: silence after a terminating line */
#define RN_SEND_TIMEOUT_MS 10000
#define RN_POLL_SLICE_MS 100       /* how often a wait looks at the ^C flag */

/* ---- ^C handling ----
 * A wait can last as long as the target takes to answer, so SIGINT has to
 * be able to end it. The previous handler (radare2's) is chained so the
 * command that triggered the request is still told about the break. */

static pthread_mutex_t g_sig_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_sig_depth = 0;
static struct sigaction g_sig_old;
static volatile sig_atomic_t g_interrupted = 0;

static void on_sigint(int sig) {
	g_interrupted = 1;
	if (!(g_sig_old.sa_flags & SA_SIGINFO)) {
		void (*h)(int) = g_sig_old.sa_handler;
		if (h != SIG_IGN && h != SIG_DFL && h != on_sigint) {
			h (sig);
		}
	}
}

static void sigint_begin(void) {
	pthread_mutex_lock (&g_sig_lock);
	if (g_sig_depth++ == 0) {
		struct sigaction sa;
		memset (&sa, 0, sizeof (sa));
		sa.sa_handler = on_sigint;
		sigemptyset (&sa.sa_mask);
		g_interrupted = 0;
		sigaction (SIGINT, &sa, &g_sig_old);
	}
	pthread_mutex_unlock (&g_sig_lock);
}

static void sigint_end(void) {
	pthread_mutex_lock (&g_sig_lock);
	if (--g_sig_depth == 0) {
		sigaction (SIGINT, &g_sig_old, NULL);
	}
	pthread_mutex_unlock (&g_sig_lock);
}

/* For a loop of short requests that must not be cut in the middle (a reply
 * that is abandoned is thrown away, and with `events` that reply is the
 * hook output): ^C is only recorded while the scope is open, and the loop
 * asks for it between requests. */
void rn_interrupt_scope_begin(RenefConn *c) {
	sigint_begin ();
	c->defer_interrupt = true;
}

bool rn_interrupt_scope_pending(void) {
	return g_interrupted != 0;
}

void rn_interrupt_scope_end(RenefConn *c) {
	c->defer_interrupt = false;
	g_interrupted = 0;
	sigint_end ();
}

/* ---- small helpers ---- */

static void stash_async(RenefConn *c, const char *data, size_t len);

static long long now_ms(void) {
	struct timespec ts;
	clock_gettime (CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int rn_env_int(const char *name, int def, int min, int max) {
	const char *v = getenv (name);
	if (!v || !*v) {
		return def;
	}
	char *end = NULL;
	errno = 0;
	long n = strtol (v, &end, 10);
	if (errno || !end || *end) {
		return def;
	}
	if (n < min) {
		return min;
	}
	if (n > max) {
		return max;
	}
	return (int)n;
}

const char *rn_status_str(RnStatus st) {
	switch (st) {
	case RN_OK: return "ok";
	case RN_TIMEOUT: return "timed out";
	case RN_CLOSED: return "connection closed by server";
	case RN_INTERRUPTED: return "interrupted";
	default: return "socket error";
	}
}

void rn_conn_lock(RenefConn *c) {
	pthread_mutex_lock (&c->lock);
}

void rn_conn_unlock(RenefConn *c) {
	pthread_mutex_unlock (&c->lock);
}

void rn_conn_init(RenefConn *c) {
	pthread_mutexattr_t attr;
	memset (c, 0, sizeof (*c));
	c->fd = -1;
	c->next_id = 1;
	rn_reader_init (&c->reader);
	rn_buf_init (&c->async);
	pthread_mutexattr_init (&attr);
	pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init (&c->lock, &attr);
	pthread_mutexattr_destroy (&attr);
	c->timeout_ms = rn_env_int ("RENEF_TIMEOUT", 35, 1, 86400) * 1000;
	c->connect_timeout_ms = rn_env_int ("RENEF_CONNECT_TIMEOUT", 5, 1, 600) * 1000;
	c->probe_timeout_ms = rn_env_int ("RENEF_PROBE_TIMEOUT_MS", 3000, 50, 600000);
	/* longer than the five seconds a public server stays in its exec
	 * handler, during which it does not even read the next command */
	c->legacy_first_ms = rn_env_int ("RENEF_LEGACY_FIRST_MS", 8000, 10, 3600000);
	c->legacy_quiet_ms = rn_env_int ("RENEF_LEGACY_QUIET_MS", 400, 10, 60000);
}

void rn_conn_close(RenefConn *c) {
	if (c->fd >= 0) {
		close (c->fd);
		c->fd = -1;
	}
}

void rn_conn_fini(RenefConn *c) {
	rn_conn_close (c);
	rn_reader_fini (&c->reader);
	rn_buf_fini (&c->async);
	pthread_mutex_destroy (&c->lock);
}

bool rn_conn_is_open(const RenefConn *c) {
	return c->fd >= 0;
}

static void set_nonblock(int fd) {
	int fl = fcntl (fd, F_GETFL, 0);
	if (fl >= 0) {
		fcntl (fd, F_SETFL, fl | O_NONBLOCK);
	}
}

void rn_conn_adopt(RenefConn *c, int fd) {
	rn_conn_close (c);
	set_nonblock (fd);
#ifdef SO_NOSIGPIPE
	{
		int one = 1;
		setsockopt (fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof (one));
	}
#endif
	c->fd = fd;
	c->framed = false;
	c->dirty = false;
	rn_reader_reset (&c->reader);
}

RnStatus rn_conn_connect(RenefConn *c, const char *host, const char *port) {
	struct addrinfo hints, *res = NULL, *ai;
	RnStatus st = RN_ERROR;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo (host, port, &hints, &res) != 0 || !res) {
		return RN_ERROR;
	}
	for (ai = res; ai; ai = ai->ai_next) {
		int fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0) {
			continue;
		}
		set_nonblock (fd);
		int rc = connect (fd, ai->ai_addr, ai->ai_addrlen);
		if (rc != 0 && errno == EINPROGRESS) {
			struct pollfd pfd = { fd, POLLOUT, 0 };
			int pr;
			do {
				pr = poll (&pfd, 1, c->connect_timeout_ms);
			} while (pr < 0 && errno == EINTR);
			if (pr > 0) {
				int err = 0;
				socklen_t el = sizeof (err);
				if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) {
					rc = 0;
				}
			} else if (pr == 0) {
				st = RN_TIMEOUT;
			}
		}
		if (rc != 0) {
			close (fd);
			continue;
		}
		int one = 1;
		setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof (one));
		rn_conn_adopt (c, fd);
		snprintf (c->host, sizeof (c->host), "%s", host);
		snprintf (c->port, sizeof (c->port), "%s", port);
		st = RN_OK;
		break;
	}
	freeaddrinfo (res);
	return st;
}

/* Waits until the socket is readable. 1 readable, 0 timeout, -1 error,
 * -2 interrupted. */
static int wait_readable(RenefConn *c, int timeout_ms) {
	long long deadline = now_ms () + timeout_ms;
	for (;;) {
		if (g_interrupted && !c->defer_interrupt) {
			return -2;
		}
		long long left = deadline - now_ms ();
		if (left < 0) {
			left = 0;
		}
		int slice = left > RN_POLL_SLICE_MS? RN_POLL_SLICE_MS: (int)left;
		struct pollfd pfd = { c->fd, POLLIN, 0 };
		int pr = poll (&pfd, 1, slice);
		if (pr > 0) {
			return 1;
		}
		if (pr < 0 && errno != EINTR) {
			return -1;
		}
		if (pr == 0 && left == 0) {
			return 0;
		}
	}
}

/* >0 bytes read, 0 nothing available right now, -1 closed, -2 error */
static ssize_t recv_some(RenefConn *c, char *buf, size_t size) {
	for (;;) {
		ssize_t n = recv (c->fd, buf, size, 0);
		if (n > 0) {
			c->rx_bytes += (unsigned long long)n;
			return n;
		}
		if (n == 0) {
			return -1;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return (errno == ECONNRESET || errno == EPIPE)? -1: -2;
	}
}

static RnStatus send_all(RenefConn *c, const char *data, size_t len) {
	long long deadline = now_ms () + RN_SEND_TIMEOUT_MS;
	size_t off = 0;
	while (off < len) {
		ssize_t n = send (c->fd, data + off, len - off, MSG_NOSIGNAL);
		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR) {
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			long long left = deadline - now_ms ();
			if (left <= 0) {
				return RN_TIMEOUT;
			}
			struct pollfd pfd = { c->fd, POLLOUT, 0 };
			poll (&pfd, 1, left > RN_POLL_SLICE_MS? RN_POLL_SLICE_MS: (int)left);
			continue;
		}
		return (errno == EPIPE || errno == ECONNRESET)? RN_CLOSED: RN_ERROR;
	}
	return RN_OK;
}

void rn_conn_stash_async(RenefConn *c, const char *data, size_t len) {
	rn_conn_lock (c);
	stash_async (c, data, len);
	rn_conn_unlock (c);
}

/* Keeps at most RN_ASYNC_MAX bytes, dropping the oldest whole lines. */
static void stash_async(RenefConn *c, const char *data, size_t len) {
	if (len == 0) {
		return;
	}
	rn_buf_append (&c->async, data, len);
	if (c->async.len > RN_ASYNC_MAX) {
		size_t drop = c->async.len - RN_ASYNC_MAX;
		const char *nl = memchr (c->async.data + drop, '\n', c->async.len - drop);
		rn_buf_consume (&c->async, nl? (size_t)(nl - c->async.data) + 1: drop);
	}
}

void rn_conn_take_async(RenefConn *c, RnBuf *out) {
	rn_conn_lock (c);
	if (c->async.len) {
		rn_buf_append (out, c->async.data, c->async.len);
		rn_buf_clear (&c->async);
	}
	rn_conn_unlock (c);
}

/* Legacy resynchronisation. A request that was given up on (timeout, ^C)
 * may still be answered later, and nothing in an unframed reply says
 * which command it belongs to. The server does answer strictly in order,
 * though: `ping` is sent as a barrier and everything that arrives before
 * its "pong" line is by construction output of the earlier commands. */
static RnStatus legacy_resync(RenefConn *c) {
	char tmp[16384];
	RnBuf got;
	RnStatus st = send_all (c, "ping\n", 5);
	if (st != RN_OK) {
		return st;
	}
	c->n_requests++;
	rn_buf_init (&got);
	for (;;) {
		/* the barrier is the last line received so far */
		if (got.len >= 5 && !memcmp (got.data + got.len - 5, "pong\n", 5)
				&& (got.len == 5 || got.data[got.len - 6] == '\n')) {
			int w = wait_readable (c, RN_LEGACY_GRACE_MS);
			if (w == 0) {
				stash_async (c, got.data, got.len - 5);
				c->dirty = false;
				st = RN_OK;
				break;
			}
			if (w == -2) {
				st = RN_INTERRUPTED;
				break;
			}
			if (w < 0) {
				st = RN_ERROR;
				break;
			}
		} else {
			int w = wait_readable (c, c->timeout_ms);
			if (w == 0) {
				st = RN_TIMEOUT;
				break;
			}
			if (w == -2) {
				st = RN_INTERRUPTED;
				break;
			}
			if (w < 0) {
				st = RN_ERROR;
				break;
			}
		}
		ssize_t n = recv_some (c, tmp, sizeof (tmp));
		if (n == -1) {
			st = RN_CLOSED;
			break;
		}
		if (n == -2) {
			st = RN_ERROR;
			break;
		}
		if (n > 0 && !rn_buf_append (&got, tmp, (size_t)n)) {
			st = RN_ERROR;
			break;
		}
	}
	if (st != RN_OK && got.len) {
		stash_async (c, got.data, got.len);
	}
	rn_buf_fini (&got);
	return st;
}

/* Bytes that are already waiting before a request goes out cannot be its
 * reply. They are output printed between commands (or the tail of a reply
 * that came too late) and are set aside instead of being thrown away or
 * mistaken for the next answer. */
static RnStatus pre_drain(RenefConn *c) {
	char tmp[16384];
	for (;;) {
		ssize_t n = recv_some (c, tmp, sizeof (tmp));
		if (n == -1) {
			return RN_CLOSED;
		}
		if (n == -2) {
			return RN_ERROR;
		}
		if (n == 0) {
			break;
		}
		if (c->framed) {
			rn_reader_feed (&c->reader, tmp, (size_t)n);
		} else {
			stash_async (c, tmp, (size_t)n);
		}
	}
	if (!c->framed && c->dirty) {
		return legacy_resync (c);
	}
	if (c->framed && c->reader.n_out == 0) {
		/* With abandoned requests still pending the bytes stay in the
		 * reader, which drops their late replies by id. */
		RnBuf a;
		rn_buf_init (&a);
		rn_reader_drain (&c->reader, &a);
		stash_async (c, a.data, a.len);
		rn_buf_fini (&a);
	}
	return RN_OK;
}

void rn_conn_poll_async(RenefConn *c) {
	rn_conn_lock (c);
	/* a pending legacy resync is left to the next request */
	if (c->fd >= 0 && (c->framed || !c->dirty)) {
		if (pre_drain (c) == RN_CLOSED) {
			rn_conn_close (c);
		}
	}
	rn_conn_unlock (c);
}

static RnStatus recv_framed(RenefConn *c, unsigned long id, int timeout_ms, RnBuf *out) {
	char tmp[65536];
	for (;;) {
		if (rn_reader_poll (&c->reader, id, out)) {
			return RN_OK;
		}
		int w = wait_readable (c, timeout_ms);
		if (w == 0) {
			return RN_TIMEOUT;
		}
		if (w == -2) {
			return RN_INTERRUPTED;
		}
		if (w < 0) {
			return RN_ERROR;
		}
		ssize_t n = recv_some (c, tmp, sizeof (tmp));
		if (n == -1) {
			return RN_CLOSED;
		}
		if (n == -2) {
			return RN_ERROR;
		}
		if (n > 0 && !rn_reader_feed (&c->reader, tmp, (size_t)n)) {
			return RN_ERROR;
		}
	}
}

/* Does the legacy reply in [data, data+len) look complete?
 * 0 no, 1 probably (confirm with a short silence), 2 certainly. */
static int legacy_terminated(const char *data, size_t len, RnLegacyEnd end) {
	if (end == RN_END_QUIET || len == 0 || data[len - 1] != '\n') {
		return 0;
	}
	if (end == RN_END_LINE) {
		return 2;
	}
	if (end == RN_END_MD) {
		/* "Memory at 0x... (N bytes):" then 16 bytes per "0x...:" line;
		 * anything else is a one-line error or usage message */
		const char *hdr = NULL;
		const char *p = data;
		const char *e = data + len;
		while (p < e) {
			const char *nl = memchr (p, '\n', (size_t)(e - p));
			if ((size_t)(nl - p) > 10 && !memcmp (p, "Memory at ", 10)) {
				hdr = p;
				break;
			}
			p = nl + 1;
		}
		if (!hdr) {
			return 1;
		}
		const char *nl = memchr (hdr, '\n', (size_t)(e - hdr));
		const char *par = memchr (hdr, '(', (size_t)(nl - hdr));
		long want = par? strtol (par + 1, NULL, 10): 0;
		long lines = 0;
		for (p = nl + 1; p < e; p = nl + 1) {
			nl = memchr (p, '\n', (size_t)(e - p));
			if (nl - p > 2 && p[0] == '0' && p[1] == 'x') {
				lines++;
			} else if (nl - p >= 5 && !memcmp (p, "ERROR", 5)) {
				return 1;
			}
		}
		return (want > 0 && lines >= (want + 15) / 16)? 2: 0;
	}
	/* RN_END_EXEC: last line is "OK" or starts with "ERROR" */
	size_t e = len - 1;
	size_t s = e;
	while (s > 0 && data[s - 1] != '\n') {
		s--;
	}
	size_t ll = e - s;
	if (ll > 0 && data[s + ll - 1] == '\r') {
		ll--;
	}
	if (ll == 2 && !memcmp (data + s, "OK", 2)) {
		if (end == RN_END_TAGGED) {
			/* A script of ours always prints a tagged line before it
			 * returns, so "OK" after one is the end and not just a
			 * line of output that happens to read OK. */
			size_t i;
			for (i = 0; i + 4 <= s; i++) {
				if ((i == 0 || data[i - 1] == '\n') && !memcmp (data + i, "@r2:", 4)) {
					return 2;
				}
			}
		}
		return 1;
	}
	return (ll >= 5 && !memcmp (data + s, "ERROR", 5))? 1: 0;
}

static RnStatus recv_legacy(RenefConn *c, RnLegacyEnd end, int timeout_ms, RnBuf *out) {
	char tmp[65536];
	size_t start = out->len;
	for (;;) {
		size_t got = out->len - start;
		int wait;
		int term = legacy_terminated (out->data? out->data + start: "", got, end);
		if (term == 2) {
			return RN_OK;
		}
		if (term) {
			wait = RN_LEGACY_GRACE_MS;
		} else if (end == RN_END_QUIET) {
			wait = got? c->legacy_quiet_ms: c->legacy_first_ms;
		} else {
			wait = timeout_ms;
		}
		int w = wait_readable (c, wait);
		if (w == 0) {
			if (term || (end == RN_END_QUIET && got)) {
				return RN_OK;
			}
			/* whatever this command still writes will show up later */
			c->dirty = true;
			return RN_TIMEOUT;
		}
		if (w == -2) {
			c->dirty = true;
			return RN_INTERRUPTED;
		}
		if (w < 0) {
			return RN_ERROR;
		}
		ssize_t n = recv_some (c, tmp, sizeof (tmp));
		if (n == -1) {
			return RN_CLOSED;
		}
		if (n == -2) {
			return RN_ERROR;
		}
		if (n > 0 && !rn_buf_append (out, tmp, (size_t)n)) {
			return RN_ERROR;
		}
	}
}

RnStatus rn_conn_request(RenefConn *c, const char *cmd, size_t cmd_len,
		RnLegacyEnd end, int timeout_ms, RnBuf *out) {
	RnBuf wire, payload;
	RnStatus st;
	unsigned long id = 0;

	if (timeout_ms <= 0) {
		timeout_ms = c->timeout_ms;
	}
	while (cmd_len > 0 && (cmd[cmd_len - 1] == '\n' || cmd[cmd_len - 1] == '\r')) {
		cmd_len--;
	}
	rn_buf_init (&wire);
	rn_buf_init (&payload);
	rn_conn_lock (c);
	if (c->fd < 0) {
		rn_conn_unlock (c);
		return RN_ERROR;
	}
	sigint_begin ();

	st = pre_drain (c);
	if (st != RN_OK) {
		goto done;
	}
	if (!rn_buf_append (&payload, cmd, cmd_len) || !rn_buf_append (&payload, "\n", 1)) {
		st = RN_ERROR;
		goto done;
	}
	if (c->framed) {
		id = c->next_id++;
		if (!rn_frame_request (&wire, id, payload.data, payload.len)) {
			st = RN_ERROR;
			goto done;
		}
		st = send_all (c, wire.data, wire.len);
	} else {
		/* a legacy command ends at its first newline */
		size_t i;
		for (i = 0; i + 1 < payload.len; i++) {
			if (payload.data[i] == '\n' || payload.data[i] == '\r') {
				payload.data[i] = ' ';
			}
		}
		st = send_all (c, payload.data, payload.len);
	}
	if (st != RN_OK) {
		goto done;
	}
	c->n_requests++;
	if (c->framed) {
		if (!rn_reader_sent (&c->reader, id)) {
			st = RN_ERROR;
			goto done;
		}
		st = recv_framed (c, id, timeout_ms, out);
	} else {
		st = recv_legacy (c, end, timeout_ms, out);
	}
done:
	sigint_end ();
	if (st == RN_CLOSED) {
		rn_conn_close (c);
	}
	rn_conn_unlock (c);
	rn_buf_fini (&wire);
	rn_buf_fini (&payload);
	return st;
}

RnStatus rn_conn_probe(RenefConn *c, RnFramingMode mode) {
	RnStatus st = RN_OK;
	RnBuf wire, out;
	char tmp[4096];

	if (c->fd < 0) {
		return RN_ERROR;
	}
	if (mode == RN_FRAMING_ON) {
		c->framed = true;
		return RN_OK;
	}
	c->framed = false;
	if (mode == RN_FRAMING_OFF) {
		return RN_OK;
	}
	rn_buf_init (&wire);
	rn_buf_init (&out);
	rn_conn_lock (c);
	sigint_begin ();

	unsigned long id = c->next_id++;
	if (!rn_frame_request (&wire, id, "ping\n", 5) || !rn_reader_sent (&c->reader, id)) {
		st = RN_ERROR;
		goto done;
	}
	st = send_all (c, wire.data, wire.len);
	if (st != RN_OK) {
		goto done;
	}
	c->n_requests++;
	long long deadline = now_ms () + c->probe_timeout_ms;
	bool got_any = false;
	bool unknown = false;
	for (;;) {
		if (rn_reader_poll (&c->reader, id, &out)) {
			c->framed = true;
			st = RN_OK;
			break;
		}
		/* An old server takes the frame for an unknown legacy command
		 * and says so on one line, with no marker to follow. */
		if (out.len && out.data[out.len - 1] == '\n' && strstr (out.data, "ERROR")) {
			unknown = true;
		}
		long long left = deadline - now_ms ();
		int wait = unknown? RN_LEGACY_GRACE_MS: (left > 0? (int)left: 0);
		int w = wait_readable (c, wait);
		if (w == 0) {
			if (unknown) {
				st = RN_OK;
			} else {
				st = got_any? RN_OK: RN_TIMEOUT;
				c->dirty = true;
			}
			break;
		}
		if (w == -2) {
			st = RN_INTERRUPTED;
			break;
		}
		if (w < 0) {
			st = RN_ERROR;
			break;
		}
		ssize_t n = recv_some (c, tmp, sizeof (tmp));
		if (n == -1) {
			st = RN_CLOSED;
			break;
		}
		if (n == -2) {
			st = RN_ERROR;
			break;
		}
		if (n > 0) {
			got_any = true;
			rn_reader_feed (&c->reader, tmp, (size_t)n);
		}
	}
	if (!c->framed) {
		rn_reader_reset (&c->reader);
	}
done:
	sigint_end ();
	if (st == RN_CLOSED) {
		rn_conn_close (c);
	}
	rn_conn_unlock (c);
	rn_buf_fini (&wire);
	rn_buf_fini (&out);
	return st;
}

/* forwards stream bytes, with completion markers of old requests removed */
static void stream_deliver(RenefConn *c, const char *data, size_t len, RnStreamCb cb, void *user) {
	if (!c->framed) {
		cb (user, data, len);
		return;
	}
	RnBuf a;
	rn_buf_init (&a);
	rn_reader_feed (&c->reader, data, len);
	rn_reader_drain (&c->reader, &a);
	if (a.len) {
		cb (user, a.data, a.len);
	}
	rn_buf_fini (&a);
}

RnStatus rn_conn_stream(RenefConn *c, const char *cmd, int max_ms, RnStreamCb cb, void *user) {
	char tmp[16384];
	RnBuf wire;
	RnStatus st;
	long long stop_at = 0;

	rn_buf_init (&wire);
	rn_conn_lock (c);
	if (c->fd < 0) {
		rn_conn_unlock (c);
		return RN_ERROR;
	}
	sigint_begin ();
	st = pre_drain (c);
	if (st != RN_OK) {
		goto done;
	}
	if (c->framed) {
		/* nothing sent before this can still be answered usefully */
		rn_reader_forget_outstanding (&c->reader);
	}
	if (!rn_buf_puts (&wire, cmd) || !rn_buf_append (&wire, "\n", 1)) {
		st = RN_ERROR;
		goto done;
	}
	st = send_all (c, wire.data, wire.len);
	if (st != RN_OK) {
		goto done;
	}
	c->n_requests++;
	if (max_ms > 0) {
		stop_at = now_ms () + max_ms;
	}
	for (;;) {
		int wait = 1000;
		if (stop_at) {
			long long left = stop_at - now_ms ();
			if (left <= 0) {
				st = RN_INTERRUPTED;
				break;
			}
			if (left < wait) {
				wait = (int)left;
			}
		}
		int w = wait_readable (c, wait);
		if (w == 0) {
			continue;
		}
		if (w == -2) {
			st = RN_INTERRUPTED;
			break;
		}
		if (w < 0) {
			st = RN_ERROR;
			break;
		}
		ssize_t n = recv_some (c, tmp, sizeof (tmp));
		if (n == -1) {
			st = RN_CLOSED;
			break;
		}
		if (n == -2) {
			st = RN_ERROR;
			break;
		}
		if (n > 0) {
			stream_deliver (c, tmp, (size_t)n, cb, user);
		}
	}
	if (st == RN_INTERRUPTED) {
		/* Any byte from the client ends a streaming command; a lone
		 * newline is not a command, so nothing else is triggered. The
		 * stream has no end marker: read its tail until it is quiet. */
		g_interrupted = 0;
		st = send_all (c, "\n", 1);
		long long hard = now_ms () + 5000;
		while (st == RN_OK && now_ms () < hard) {
			int w = wait_readable (c, c->legacy_quiet_ms);
			if (w <= 0) {
				break;
			}
			ssize_t n = recv_some (c, tmp, sizeof (tmp));
			if (n == -1) {
				st = RN_CLOSED;
			} else if (n == -2) {
				st = RN_ERROR;
			} else if (n > 0) {
				stream_deliver (c, tmp, (size_t)n, cb, user);
			}
		}
	}
done:
	sigint_end ();
	if (st == RN_CLOSED) {
		rn_conn_close (c);
	}
	rn_conn_unlock (c);
	rn_buf_fini (&wire);
	return st;
}
