/* r2renef - MIT - Copyright 2025-2026 */

/*
 * Unit tests for src/renef_socket.c. The "server" is a thread on the other
 * end of a socketpair that plays a scripted renef_server: it can answer
 * late, in tiny pieces, without being asked, or not at all.
 */

#include "../src/renef_socket.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int g_checks = 0;
static int g_failed = 0;

#define CHECK(cond) do { \
	g_checks++; \
	if (!(cond)) { \
		g_failed++; \
		fprintf (stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

static long long now_ms(void) {
	struct timespec ts;
	clock_gettime (CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void msleep(int ms) {
	usleep ((useconds_t)ms * 1000);
}

/* ---- scripted server side ---- */

static void srv_send(int fd, const char *data, size_t len, size_t chunk, int gap_ms) {
	size_t off = 0;
	if (chunk == 0) {
		chunk = len;
	}
	while (off < len) {
		size_t n = len - off < chunk? len - off: chunk;
		if (write (fd, data + off, n) != (ssize_t)n) {
			return;
		}
		off += n;
		if (gap_ms && off < len) {
			msleep (gap_ms);
		}
	}
}

static void srv_puts(int fd, const char *s) {
	srv_send (fd, s, strlen (s), 0, 0);
}

/* reads one '\n' terminated line (without the newline); false on EOF */
static bool srv_line(int fd, char *buf, size_t size) {
	size_t n = 0;
	for (;;) {
		char c;
		if (read (fd, &c, 1) != 1) {
			return false;
		}
		if (c == '\n') {
			buf[n] = '\0';
			return true;
		}
		if (n + 1 < size) {
			buf[n++] = c;
		}
	}
}

/* reads one framed request; returns its id (0 on EOF or if unframed) */
static unsigned long srv_frame(int fd, char *payload, size_t size) {
	char hdr[64];
	unsigned long id = 0;
	size_t len = 0, got = 0;
	if (!srv_line (fd, hdr, sizeof (hdr)) || sscanf (hdr, "@req %lu %zu", &id, &len) != 2) {
		return 0;
	}
	while (got < len) {
		char c;
		if (read (fd, &c, 1) != 1) {
			return 0;
		}
		if (got + 1 < size) {
			payload[got] = c;
		}
		got++;
	}
	payload[got < size? got: size - 1] = '\0';
	return id;
}

static void srv_done(int fd, unsigned long id) {
	char m[32];
	snprintf (m, sizeof (m), "\x1e@done %lu\n", id);
	srv_puts (fd, m);
}

typedef void (*SrvFn)(int fd);

typedef struct {
	int fd;
	SrvFn fn;
} SrvArg;

static void *srv_thread(void *p) {
	SrvArg *a = p;
	a->fn (a->fd);
	close (a->fd);
	free (a);
	return NULL;
}

/* sets up a connection whose peer runs `fn` */
static pthread_t start(RenefConn *c, SrvFn fn) {
	int sv[2];
	pthread_t th;
	if (socketpair (AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		perror ("socketpair");
		exit (2);
	}
	rn_conn_init (c);
	rn_conn_adopt (c, sv[0]);
	c->timeout_ms = 2000;
	c->probe_timeout_ms = 300;
	c->legacy_first_ms = 300;
	c->legacy_quiet_ms = 150;
	SrvArg *a = malloc (sizeof (SrvArg));
	a->fd = sv[1];
	a->fn = fn;
	pthread_create (&th, NULL, srv_thread, a);
	return th;
}

static void finish(RenefConn *c, pthread_t th) {
	rn_conn_close (c);
	pthread_join (th, NULL);
	rn_conn_fini (c);
}

/* ---- framed ---- */

static void srv_framed_basic(int fd) {
	char p[256];
	unsigned long id = srv_frame (fd, p, sizeof (p));       /* probe */
	srv_puts (fd, "pong\n");
	srv_done (fd, id);
	id = srv_frame (fd, p, sizeof (p));
	if (strcmp (p, "exec print(1)\n")) {
		srv_puts (fd, "BAD REQUEST\n");
	}
	/* one byte at a time: the marker is split across every read */
	char reply[64];
	int n = snprintf (reply, sizeof (reply), "1\nOK\n\x1e@done %lu\n", id);
	srv_send (fd, reply, (size_t)n, 1, 1);
	id = srv_frame (fd, p, sizeof (p));
	srv_send (fd, "a\0b\n\x1e@don\x1e", 10, 3, 1);         /* NULs and a near-marker */
	srv_done (fd, id);
	/* 1MB in 4KB pieces */
	id = srv_frame (fd, p, sizeof (p));
	char *big = malloc (1 << 20);
	size_t i;
	for (i = 0; i < (1 << 20); i++) {
		big[i] = (char)(i * 31);
	}
	srv_send (fd, big, 1 << 20, 4096, 0);
	free (big);
	srv_done (fd, id);
}

static void test_framed_basic(void) {
	RenefConn c;
	RnBuf out;
	pthread_t th = start (&c, srv_framed_basic);
	rn_buf_init (&out);

	CHECK (rn_conn_probe (&c, RN_FRAMING_AUTO) == RN_OK);
	CHECK (c.framed);
	CHECK (rn_conn_request (&c, "exec print(1)", 13, RN_END_EXEC, 0, &out) == RN_OK);
	CHECK (out.len == 5 && !memcmp (out.data, "1\nOK\n", 5));

	rn_buf_clear (&out);
	CHECK (rn_conn_request (&c, "x", 1, RN_END_QUIET, 0, &out) == RN_OK);
	CHECK (out.len == 10 && !memcmp (out.data, "a\0b\n\x1e@don\x1e", 10));

	rn_buf_clear (&out);
	CHECK (rn_conn_request (&c, "big", 3, RN_END_QUIET, 0, &out) == RN_OK);
	CHECK (out.len == (1 << 20));
	size_t i, bad = 0;
	for (i = 0; i < out.len; i++) {
		bad += out.data[i] != (char)(i * 31);
	}
	CHECK (bad == 0);

	rn_buf_fini (&out);
	finish (&c, th);
}

static void srv_framed_stale(int fd) {
	char p[256];
	unsigned long a = srv_frame (fd, p, sizeof (p));
	unsigned long b = srv_frame (fd, p, sizeof (p));        /* arrives while A "runs" */
	msleep (350);
	srv_puts (fd, "A-late A-late A-late A-late\n");
	srv_done (fd, a);
	srv_puts (fd, "B\n");
	srv_done (fd, b);
	unsigned long d = srv_frame (fd, p, sizeof (p));
	srv_puts (fd, "D\n");
	srv_done (fd, d);
}

static void test_framed_stale(void) {
	RenefConn c;
	RnBuf out, async;
	pthread_t th = start (&c, srv_framed_stale);
	rn_buf_init (&out);
	rn_buf_init (&async);
	c.framed = true;

	/* A is given up on after 100ms; its reply shows up later */
	long long t0 = now_ms ();
	CHECK (rn_conn_request (&c, "A", 1, RN_END_EXEC, 100, &out) == RN_TIMEOUT);
	CHECK (now_ms () - t0 < 300 && out.len == 0);
	/* B must get B's reply, not A's */
	CHECK (rn_conn_request (&c, "B", 1, RN_END_EXEC, 0, &out) == RN_OK);
	CHECK (out.len == 2 && !memcmp (out.data, "B\n", 2));
	rn_buf_clear (&out);
	CHECK (rn_conn_request (&c, "D", 1, RN_END_EXEC, 0, &out) == RN_OK);
	CHECK (out.len == 2 && !memcmp (out.data, "D\n", 2));
	/* the late reply is dropped, not shown as stray output */
	rn_conn_take_async (&c, &async);
	CHECK (async.len == 0);

	rn_buf_fini (&out);
	rn_buf_fini (&async);
	finish (&c, th);
}

static void srv_framed_unsolicited(int fd) {
	char p[256];
	srv_puts (fd, "[hook] fired while idle\n");
	unsigned long id = srv_frame (fd, p, sizeof (p));
	srv_puts (fd, "answer\n");
	srv_done (fd, id);
}

static void test_framed_unsolicited(void) {
	RenefConn c;
	RnBuf out, async;
	pthread_t th = start (&c, srv_framed_unsolicited);
	rn_buf_init (&out);
	rn_buf_init (&async);
	c.framed = true;
	msleep (60);
	CHECK (rn_conn_request (&c, "q", 1, RN_END_EXEC, 0, &out) == RN_OK);
	CHECK (out.len == 7 && !memcmp (out.data, "answer\n", 7));
	rn_conn_take_async (&c, &async);
	CHECK (async.len == 24 && !memcmp (async.data, "[hook] fired while idle\n", 24));
	rn_buf_fini (&out);
	rn_buf_fini (&async);
	finish (&c, th);
}

/* ---- probe ---- */

static void srv_probe_legacy(int fd) {
	char p[256];
	/* an old server reads "@req 1 5\nping\n" as one unknown command */
	srv_line (fd, p, sizeof (p));
	srv_line (fd, p, sizeof (p));
	msleep (50);
	static const char unknown[] = "ERROR: Unknown command. Type 'help' for available commands.\n";
	srv_send (fd, unknown, sizeof (unknown) - 1, 7, 1);
	srv_line (fd, p, sizeof (p));
	if (!strcmp (p, "ping")) {
		srv_puts (fd, "pong\n");
	}
}

static void test_probe_legacy(void) {
	RenefConn c;
	RnBuf out;
	pthread_t th = start (&c, srv_probe_legacy);
	rn_buf_init (&out);
	CHECK (rn_conn_probe (&c, RN_FRAMING_AUTO) == RN_OK);
	CHECK (!c.framed && !c.dirty);
	CHECK (rn_conn_request (&c, "ping", 4, RN_END_LINE, 0, &out) == RN_OK);
	CHECK (out.len == 5 && !memcmp (out.data, "pong\n", 5));
	rn_buf_fini (&out);
	finish (&c, th);
}

static void srv_silent(int fd) {
	char p[256];
	srv_line (fd, p, sizeof (p));
	msleep (600);
}

static void test_probe_silent(void) {
	RenefConn c;
	pthread_t th = start (&c, srv_silent);
	long long t0 = now_ms ();
	/* another client holds the server: nothing comes back at all */
	CHECK (rn_conn_probe (&c, RN_FRAMING_AUTO) == RN_TIMEOUT);
	CHECK (now_ms () - t0 >= 250 && now_ms () - t0 < 550);
	finish (&c, th);
}

static void test_probe_forced(void) {
	RenefConn c;
	pthread_t th = start (&c, srv_silent);
	CHECK (rn_conn_probe (&c, RN_FRAMING_ON) == RN_OK && c.framed);
	CHECK (rn_conn_probe (&c, RN_FRAMING_OFF) == RN_OK && !c.framed);
	finish (&c, th);
}

/* ---- legacy ---- */

static void srv_legacy_shapes(int fd) {
	char p[256];
	srv_line (fd, p, sizeof (p));                           /* spawn */
	srv_send (fd, "OK 12", 5, 0, 0);
	msleep (120);                                           /* reply split by the network */
	srv_puts (fd, "34\n");

	srv_line (fd, p, sizeof (p));                           /* exec */
	srv_puts (fd, "line\nOK but not the status\nO");
	msleep (200);                                           /* longer than the quiet window */
	srv_puts (fd, "K\n");

	srv_line (fd, p, sizeof (p));                           /* md */
	static const char md1[] =
		"Memory at 0x1000 (20 bytes):\n"
		"0x00001000:  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  |................|\n";
	srv_send (fd, md1, sizeof (md1) - 1, 9, 2);
	msleep (200);
	srv_puts (fd, "0x00001010:  10 11 12 13                                      |....|\n");

	srv_line (fd, p, sizeof (p));                           /* md of an unmapped address */
	srv_puts (fd, "ERROR: Invalid memory address or access violation\n");

	srv_line (fd, p, sizeof (p));                           /* something of unknown shape */
	srv_puts (fd, "a\n");
	msleep (60);
	srv_puts (fd, "b\n");

	srv_line (fd, p, sizeof (p));                           /* a command that prints nothing */
	msleep (700);
}

static void test_legacy_shapes(void) {
	RenefConn c;
	RnBuf out;
	pthread_t th = start (&c, srv_legacy_shapes);
	rn_buf_init (&out);
	c.legacy_quiet_ms = 150;

	/* a one-line reply is complete at its newline, however it was split */
	CHECK (rn_conn_request (&c, "spawn com.x", 11, RN_END_LINE, 0, &out) == RN_OK);
	CHECK (out.len == 8 && !memcmp (out.data, "OK 1234\n", 8));

	/* exec: ends with its status line, even when that is split by a
	 * pause longer than the quiet window */
	rn_buf_clear (&out);
	CHECK (rn_conn_request (&c, "exec x", 6, RN_END_EXEC, 0, &out) == RN_OK);
	CHECK (out.len == 30 && !memcmp (out.data, "line\nOK but not the status\nOK\n", 30));

	/* md: complete when the announced bytes are there - not earlier
	 * (the pause) and without waiting for the line to go quiet */
	rn_buf_clear (&out);
	c.legacy_quiet_ms = 3000;
	long long t0 = now_ms ();
	CHECK (rn_conn_request (&c, "md 0x1000 20", 12, RN_END_MD, 0, &out) == RN_OK);
	CHECK (now_ms () - t0 < 1500);
	uint8_t bytes[32];
	CHECK (rn_parse_md (out.data, out.len, 0x1000, bytes, sizeof (bytes)) == 20);
	CHECK (bytes[0] == 0 && bytes[19] == 0x13);

	rn_buf_clear (&out);
	t0 = now_ms ();
	CHECK (rn_conn_request (&c, "md 0x0 16", 9, RN_END_MD, 0, &out) == RN_OK);
	CHECK (now_ms () - t0 < 1500 && !strncmp (out.data, "ERROR", 5));

	/* unknown shape: until the line goes quiet */
	rn_buf_clear (&out);
	c.legacy_quiet_ms = 150;
	CHECK (rn_conn_request (&c, "la", 2, RN_END_QUIET, 0, &out) == RN_OK);
	CHECK (out.len == 4 && !memcmp (out.data, "a\nb\n", 4));

	/* no output at all is a timeout after legacy_first_ms, not a hang */
	rn_buf_clear (&out);
	t0 = now_ms ();
	CHECK (rn_conn_request (&c, "quiet", 5, RN_END_QUIET, 0, &out) == RN_TIMEOUT);
	CHECK (now_ms () - t0 >= 250 && now_ms () - t0 < 1000 && out.len == 0);

	rn_buf_fini (&out);
	finish (&c, th);
}

static void srv_legacy_resync(int fd) {
	char p[256];
	srv_line (fd, p, sizeof (p));                           /* A */
	msleep (350);
	srv_puts (fd, "A-late\nOK\n");
	/* the client must synchronise before B: answer in order */
	for (;;) {
		if (!srv_line (fd, p, sizeof (p))) {
			return;
		}
		if (!strcmp (p, "ping")) {
			srv_puts (fd, "pong\n");
		} else if (!strcmp (p, "exec B")) {
			srv_puts (fd, "B\nOK\n");
		} else {
			srv_puts (fd, "ERROR: unexpected\n");
		}
	}
}

static void test_legacy_resync(void) {
	RenefConn c;
	RnBuf out, async;
	pthread_t th = start (&c, srv_legacy_resync);
	rn_buf_init (&out);
	rn_buf_init (&async);

	CHECK (rn_conn_request (&c, "exec A", 6, RN_END_EXEC, 100, &out) == RN_TIMEOUT);
	CHECK (c.dirty);
	/* Without a barrier B would be handed A's late reply and every
	 * later command the reply of the one before it. */
	CHECK (rn_conn_request (&c, "exec B", 6, RN_END_EXEC, 0, &out) == RN_OK);
	CHECK (out.len == 5 && !memcmp (out.data, "B\nOK\n", 5));
	CHECK (!c.dirty);
	rn_conn_take_async (&c, &async);
	CHECK (async.len == 10 && !memcmp (async.data, "A-late\nOK\n", 10));
	rn_buf_clear (&out);
	CHECK (rn_conn_request (&c, "exec B", 6, RN_END_EXEC, 0, &out) == RN_OK);
	CHECK (out.len == 5 && !memcmp (out.data, "B\nOK\n", 5));

	rn_buf_fini (&out);
	rn_buf_fini (&async);
	finish (&c, th);
}

/* ---- connection loss ---- */

static void srv_close_early(int fd) {
	char p[256];
	srv_line (fd, p, sizeof (p));
	srv_puts (fd, "partial");
}

static void test_closed(void) {
	RenefConn c;
	RnBuf out;
	pthread_t th = start (&c, srv_close_early);
	rn_buf_init (&out);
	CHECK (rn_conn_request (&c, "exec x", 6, RN_END_EXEC, 0, &out) == RN_CLOSED);
	CHECK (!rn_conn_is_open (&c));
	CHECK (rn_conn_request (&c, "exec y", 6, RN_END_EXEC, 0, &out) == RN_ERROR);
	rn_buf_fini (&out);
	finish (&c, th);
}

/* ---- streaming ---- */

static void srv_watch(int fd) {
	char p[256];
	srv_line (fd, p, sizeof (p));
	if (strcmp (p, "watch")) {
		return;
	}
	srv_puts (fd, "Watching hook output...\n");
	/* stream until the client sends anything */
	for (;;) {
		fd_set rf;
		struct timeval tv = { 0, 30000 };
		FD_ZERO (&rf);
		FD_SET (fd, &rf);
		if (select (fd + 1, &rf, NULL, NULL, &tv) > 0) {
			char stop[31];
			if (read (fd, stop, sizeof (stop)) <= 0) {
				return;
			}
			break;
		}
		srv_puts (fd, "tick\n");
	}
	srv_puts (fd, "tail\n");
	unsigned long id = srv_frame (fd, p, sizeof (p));
	srv_puts (fd, "pong\n");
	srv_done (fd, id);
}

static void stream_cb(void *user, const char *data, size_t len) {
	rn_buf_append (user, data, len);
}

static void test_stream(void) {
	RenefConn c;
	RnBuf got, out;
	pthread_t th = start (&c, srv_watch);
	rn_buf_init (&got);
	rn_buf_init (&out);
	c.framed = true;
	long long t0 = now_ms ();
	CHECK (rn_conn_stream (&c, "watch", 200, stream_cb, &got) == RN_OK);
	CHECK (now_ms () - t0 >= 200 && now_ms () - t0 < 1500);
	CHECK (got.data && strstr (got.data, "Watching hook output...\n") == got.data);
	CHECK (got.data && strstr (got.data, "tick\n") != NULL);
	/* the stream's tail is read before the next command goes out */
	CHECK (got.len >= 5 && !memcmp (got.data + got.len - 5, "tail\n", 5));
	CHECK (rn_conn_request (&c, "ping", 4, RN_END_LINE, 0, &out) == RN_OK);
	CHECK (out.len == 5 && !memcmp (out.data, "pong\n", 5));
	rn_buf_fini (&got);
	rn_buf_fini (&out);
	finish (&c, th);
}

/* ---- environment ---- */

static void test_env(void) {
	unsetenv ("RN_TEST_INT");
	CHECK (rn_env_int ("RN_TEST_INT", 7, 1, 10) == 7);
	setenv ("RN_TEST_INT", "5", 1);
	CHECK (rn_env_int ("RN_TEST_INT", 7, 1, 10) == 5);
	setenv ("RN_TEST_INT", "500", 1);
	CHECK (rn_env_int ("RN_TEST_INT", 7, 1, 10) == 10);
	setenv ("RN_TEST_INT", "-3", 1);
	CHECK (rn_env_int ("RN_TEST_INT", 7, 1, 10) == 1);
	setenv ("RN_TEST_INT", "12abc", 1);
	CHECK (rn_env_int ("RN_TEST_INT", 7, 1, 10) == 7);
	setenv ("RN_TEST_INT", "", 1);
	CHECK (rn_env_int ("RN_TEST_INT", 7, 1, 10) == 7);
}

int main(void) {
	test_env ();
	test_framed_basic ();
	test_framed_stale ();
	test_framed_unsolicited ();
	test_probe_legacy ();
	test_probe_silent ();
	test_probe_forced ();
	test_legacy_shapes ();
	test_legacy_resync ();
	test_closed ();
	test_stream ();
	printf ("test_socket: %d checks, %d failed\n", g_checks, g_failed);
	return g_failed? 1: 0;
}
