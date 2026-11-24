/* r2renef - MIT - Copyright 2025-2026 */

/*
 * Connection to renef_server. Plain POSIX sockets, no radare2 dependency.
 *
 * Two request modes:
 *   framed  "@req <id> <len>\n<payload>" answered by "...\x1e@done <id>\n".
 *           The reply ends exactly at its marker; a reply that arrives
 *           after its request was given up on is skipped by id.
 *   legacy  "<cmd>\n", the reply is whatever arrives until the line goes
 *           quiet (public renef <= 0.3.7 knows nothing else).
 * Which one is used is decided once per connection by rn_conn_probe().
 */

#ifndef RENEF_SOCKET_H
#define RENEF_SOCKET_H

#include <pthread.h>
#include "renef_proto.h"

#define RN_DEFAULT_HOST "127.0.0.1"
#define RN_DEFAULT_PORT "1907"

typedef enum {
	RN_OK = 0,
	RN_TIMEOUT,      /* no (complete) reply in time; partial data is kept */
	RN_CLOSED,       /* server closed the connection */
	RN_INTERRUPTED,  /* ^C while waiting */
	RN_ERROR         /* socket error / out of memory / not connected */
} RnStatus;

/* How a legacy (unframed) reply is known to be complete. Ignored for
 * framed requests, which always end at their marker. */
typedef enum {
	RN_END_QUIET = 0, /* unknown shape: read until the line goes quiet */
	RN_END_LINE,      /* reply is one line (spawn, attach, ping) */
	RN_END_EXEC,      /* reply ends with exec's "OK" / "ERROR..." status line */
	RN_END_TAGGED,    /* exec whose script prints "@r2:" lines: those plus "OK" end it */
	RN_END_MD         /* reply is an `md` dump of the announced size, or one error line */
} RnLegacyEnd;

typedef enum {
	RN_FRAMING_AUTO = 0,
	RN_FRAMING_ON,
	RN_FRAMING_OFF
} RnFramingMode;

typedef struct {
	int fd;
	bool framed;
	bool dirty;              /* legacy: a late reply may still be on the wire */
	bool defer_interrupt;    /* ^C does not end a wait (see rn_interrupt_scope_begin) */
	unsigned long next_id;
	RnReader reader;
	RnBuf async;             /* output nobody asked for (hook callbacks, ...) */
	pthread_mutex_t lock;    /* one request/response exchange at a time */
	int timeout_ms;          /* inactivity limit while waiting for a reply */
	int connect_timeout_ms;
	int probe_timeout_ms;
	int legacy_first_ms;     /* RN_END_QUIET: wait for the first byte */
	int legacy_quiet_ms;     /* RN_END_QUIET: silence that ends a reply */
	char host[256];
	char port[8];
	unsigned long n_requests;
	unsigned long long rx_bytes;
} RenefConn;

typedef void (*RnStreamCb)(void *user, const char *data, size_t len);

/* integer from the environment, clamped to [min, max]; def if unset/bad */
int rn_env_int(const char *name, int def, int min, int max);

void rn_conn_init(RenefConn *c);
void rn_conn_fini(RenefConn *c);
/* Wraps an already connected stream socket (tests use a socketpair). */
void rn_conn_adopt(RenefConn *c, int fd);
RnStatus rn_conn_connect(RenefConn *c, const char *host, const char *port);
void rn_conn_close(RenefConn *c);
bool rn_conn_is_open(const RenefConn *c);

/* ^C handling for a loop of short requests: inside the scope a request is
 * never ended by ^C (its reply would be lost), the loop polls
 * rn_interrupt_scope_pending() between requests instead. */
void rn_interrupt_scope_begin(RenefConn *c);
bool rn_interrupt_scope_pending(void);
void rn_interrupt_scope_end(RenefConn *c);

/* Decides framed vs legacy. With RN_FRAMING_AUTO a framed `ping` is sent:
 * a framing-aware server completes it with a marker, an old one answers
 * "ERROR: Unknown command". RN_TIMEOUT means nothing came back at all. */
RnStatus rn_conn_probe(RenefConn *c, RnFramingMode mode);

/* Sends one command (no trailing newline needed) and collects its reply
 * into `out` (appended). timeout_ms <= 0 selects the connection default.
 * On RN_TIMEOUT / RN_INTERRUPTED `out` holds what arrived so far. */
RnStatus rn_conn_request(RenefConn *c, const char *cmd, size_t cmd_len,
	RnLegacyEnd end, int timeout_ms, RnBuf *out);

/* Sends `cmd` unframed and forwards everything the server writes to `cb`
 * until ^C, EOF or (if max_ms > 0) max_ms have passed, then tells the
 * server to stop (any byte ends `watch`) and forwards the tail. Returns
 * RN_OK when the stream was stopped that way. */
RnStatus rn_conn_stream(RenefConn *c, const char *cmd, int max_ms, RnStreamCb cb, void *user);

/* Collects whatever the server has written without being asked. */
void rn_conn_poll_async(RenefConn *c);
/* Moves buffered unsolicited output into `out`. */
void rn_conn_take_async(RenefConn *c, RnBuf *out);
/* Files bytes as unsolicited output (lines of a reply that were not part
 * of the answer, e.g. a hook callback printing in the middle of it). */
void rn_conn_stash_async(RenefConn *c, const char *data, size_t len);

void rn_conn_lock(RenefConn *c);
void rn_conn_unlock(RenefConn *c);

const char *rn_status_str(RnStatus st);

#endif
