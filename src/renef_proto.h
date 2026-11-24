/* r2renef - MIT - Copyright 2025-2026 */

/*
 * Wire-level helpers that do not depend on radare2: byte buffers, request
 * framing, reply parsers. Kept free of r2 headers so tests/ can build and
 * exercise them standalone.
 */

#ifndef RENEF_PROTO_H
#define RENEF_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- growable byte buffer (binary safe, always NUL terminated) ---- */

typedef struct {
	char *data;
	size_t len;
	size_t cap;
} RnBuf;

void rn_buf_init(RnBuf *b);
void rn_buf_fini(RnBuf *b);
void rn_buf_clear(RnBuf *b);
bool rn_buf_append(RnBuf *b, const void *data, size_t n);
bool rn_buf_appendf(RnBuf *b, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
bool rn_buf_puts(RnBuf *b, const char *s);
/* drops the first n bytes */
void rn_buf_consume(RnBuf *b, size_t n);
/* hands the storage to the caller (NUL terminated, never NULL on success) */
char *rn_buf_steal(RnBuf *b, size_t *len);

/* ---- request framing (mirrors renef/framing.h) ----
 *
 *   request :  "@req <id> <len>\n" followed by exactly <len> bytes
 *   response:  <everything the command wrote> "\x1e@done <id>[ ev=<n>]\n"
 */

#define RN_DONE_MARK "\x1e@done "
#define RN_DONE_MARK_LEN 7
#define RN_REQ_PREFIX "@req "

/* appends a complete request frame for `payload` to `out` */
bool rn_frame_request(RnBuf *out, unsigned long id, const void *payload, size_t len);

/* Requester side: demultiplexes a response byte stream by request id.
 * A straight port of renef_framing::ResponseReader. */
typedef struct {
	RnBuf buf;
	unsigned long *outstanding;
	size_t n_out;
	size_t cap_out;
	/* "ev=<n>" of the marker that completed the last request: lines of
	 * hook/trace output waiting on the server (they are never part of a
	 * reply; `events` fetches them). 0 when the server does not say. */
	unsigned long pending_events;
} RnReader;

void rn_reader_init(RnReader *r);
void rn_reader_fini(RnReader *r);
void rn_reader_reset(RnReader *r);
void rn_reader_forget_outstanding(RnReader *r);
bool rn_reader_sent(RnReader *r, unsigned long id);
bool rn_reader_feed(RnReader *r, const void *data, size_t n);
bool rn_reader_busy_with_older(const RnReader *r, unsigned long id);
/* Consumes buffered bytes on behalf of request `id`: bytes that belong to
 * it are appended to `out`, bytes of older (abandoned) requests are
 * dropped. Returns true once the completion marker of `id` was consumed. */
bool rn_reader_poll(RnReader *r, unsigned long id, RnBuf *out);
/* Hands out everything buffered that is not part of a completion marker
 * (output that arrived while no request was being waited for). */
void rn_reader_drain(RnReader *r, RnBuf *out);

/* ---- reply parsers ---- */

/* Parses the ASCII dump printed by `md <addr> <size>`:
 *
 *   Memory at 0x7f8a1c2000 (32 bytes):
 *   0x7f8a1c2000:  7f 45 4c 46 ...  |.ELF............|
 *
 * Only lines whose address continues the dump at `addr` are accepted, so
 * unrelated output on the same stream cannot inject bytes. Returns the
 * number of bytes stored in `out` (<= max), or -1 when the reply holds no
 * dump for `addr`. `resp` does not have to be NUL terminated. */
int rn_parse_md(const char *resp, size_t resp_len, uint64_t addr, uint8_t *out, int max);

/* Decodes exactly `hex_len` hex digits. Returns the byte count or -1 if
 * the input is odd sized, too long for `max`, or not hex. */
int rn_hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t max);

typedef struct {
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	char perms[5];
	char path[256];
} RnMapLine;

/* Parses one /proc/<pid>/maps line (need not be NUL terminated). */
bool rn_parse_maps_line(const char *line, size_t len, RnMapLine *out);

/* ---- URI ---- */

typedef struct {
	char host[256];
	char port[8];
	bool spawn;        /* false = attach */
	char target[256];  /* package name or pid */
} RnUri;

/* Accepts "[renef://][host[:port]/]<spawn|attach>/<target>". Missing host
 * or port are taken from `def_host` / `def_port`. On failure returns false
 * and points *err at a static message. */
bool rn_parse_uri(const char *uri, const char *def_host, const char *def_port, RnUri *out, const char **err);

/* ---- Lua helpers ---- */

/* Appends `s` as a double-quoted Lua string literal. The result never
 * contains a newline or "//" (renef_server would split the command name at
 * the latter). */
bool rn_lua_quote(RnBuf *out, const char *s, size_t len);

/* Appends the hex digits of `data` (lower case). */
bool rn_hex_encode(RnBuf *out, const void *data, size_t len);

/* Appends a Lua statement that runs `script` (any bytes: newlines,
 * comments, "//") in the target. The chunk travels hex encoded and is
 * rebuilt with load(), so it is one line with no character the command
 * protocol could trip over, and errors are printed with file:line. */
bool rn_lua_wrap_script(RnBuf *out, const char *script, size_t len, const char *chunkname);

/* Appends the standard base64 encoding of `data`. */
bool rn_base64_encode(RnBuf *out, const void *data, size_t len);

/* Turns a search pattern into the spaced form Memory.search() treats as a
 * byte pattern ("50 4B ?? 04 "). With is_hex the input is hex digits where
 * "??" or ".." is a wildcard byte and blanks are ignored; otherwise the
 * input is literal bytes. Returns a malloc'd string or NULL (bad input,
 * empty, or longer than 256 bytes). */
char *rn_search_pattern(const char *in, size_t len, bool is_hex);

#endif
