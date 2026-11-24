/* r2renef - MIT - Copyright 2025-2026 */

#include "renef_proto.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- RnBuf ---- */

void rn_buf_init(RnBuf *b) {
	b->data = NULL;
	b->len = 0;
	b->cap = 0;
}

void rn_buf_fini(RnBuf *b) {
	free (b->data);
	rn_buf_init (b);
}

void rn_buf_clear(RnBuf *b) {
	b->len = 0;
	if (b->data) {
		b->data[0] = '\0';
	}
}

static bool rn_buf_reserve(RnBuf *b, size_t extra) {
	if (extra > SIZE_MAX - b->len - 1) {
		return false;
	}
	size_t need = b->len + extra + 1;
	if (need <= b->cap) {
		return true;
	}
	size_t ncap = b->cap? b->cap: 256;
	while (ncap < need) {
		if (ncap > SIZE_MAX / 2) {
			ncap = need;
			break;
		}
		ncap *= 2;
	}
	char *nd = realloc (b->data, ncap);
	if (!nd) {
		return false;
	}
	b->data = nd;
	b->cap = ncap;
	return true;
}

bool rn_buf_append(RnBuf *b, const void *data, size_t n) {
	if (!rn_buf_reserve (b, n)) {
		return false;
	}
	if (n) {
		memcpy (b->data + b->len, data, n);
	}
	b->len += n;
	b->data[b->len] = '\0';
	return true;
}

bool rn_buf_puts(RnBuf *b, const char *s) {
	return rn_buf_append (b, s, strlen (s));
}

bool rn_buf_appendf(RnBuf *b, const char *fmt, ...) {
	va_list ap, ap2;
	va_start (ap, fmt);
	va_copy (ap2, ap);
	int n = vsnprintf (NULL, 0, fmt, ap);
	va_end (ap);
	if (n < 0 || !rn_buf_reserve (b, (size_t)n)) {
		va_end (ap2);
		return false;
	}
	vsnprintf (b->data + b->len, (size_t)n + 1, fmt, ap2);
	va_end (ap2);
	b->len += (size_t)n;
	return true;
}

void rn_buf_consume(RnBuf *b, size_t n) {
	if (n >= b->len) {
		rn_buf_clear (b);
		return;
	}
	memmove (b->data, b->data + n, b->len - n);
	b->len -= n;
	b->data[b->len] = '\0';
}

char *rn_buf_steal(RnBuf *b, size_t *len) {
	if (!b->data && !rn_buf_reserve (b, 0)) {
		return NULL;
	}
	char *d = b->data;
	d[b->len] = '\0';
	if (len) {
		*len = b->len;
	}
	rn_buf_init (b);
	return d;
}

/* ---- framing ---- */

bool rn_frame_request(RnBuf *out, unsigned long id, const void *payload, size_t len) {
	return rn_buf_appendf (out, RN_REQ_PREFIX "%lu %zu\n", id, len)
		&& rn_buf_append (out, payload, len);
}

void rn_reader_init(RnReader *r) {
	rn_buf_init (&r->buf);
	r->outstanding = NULL;
	r->n_out = 0;
	r->cap_out = 0;
	r->pending_events = 0;
}

void rn_reader_fini(RnReader *r) {
	rn_buf_fini (&r->buf);
	free (r->outstanding);
	r->outstanding = NULL;
	r->n_out = 0;
	r->cap_out = 0;
}

void rn_reader_reset(RnReader *r) {
	rn_buf_clear (&r->buf);
	r->n_out = 0;
	r->pending_events = 0;
}

void rn_reader_forget_outstanding(RnReader *r) {
	r->n_out = 0;
}

bool rn_reader_sent(RnReader *r, unsigned long id) {
	if (r->n_out == r->cap_out) {
		size_t ncap = r->cap_out? r->cap_out * 2: 8;
		unsigned long *n = realloc (r->outstanding, ncap * sizeof (*n));
		if (!n) {
			return false;
		}
		r->outstanding = n;
		r->cap_out = ncap;
	}
	r->outstanding[r->n_out++] = id;
	return true;
}

bool rn_reader_feed(RnReader *r, const void *data, size_t n) {
	return rn_buf_append (&r->buf, data, n);
}

bool rn_reader_busy_with_older(const RnReader *r, unsigned long id) {
	return r->n_out > 0 && r->outstanding[0] < id;
}

/* offset of the first completion marker in buf, or (size_t)-1 */
static size_t find_mark(const RnBuf *b) {
	if (b->len < RN_DONE_MARK_LEN) {
		return (size_t)-1;
	}
	const char *p = b->data;
	const char *end = b->data + b->len - RN_DONE_MARK_LEN + 1;
	while (p < end) {
		p = memchr (p, RN_DONE_MARK[0], (size_t)(end - p));
		if (!p) {
			break;
		}
		if (!memcmp (p, RN_DONE_MARK, RN_DONE_MARK_LEN)) {
			return (size_t)(p - b->data);
		}
		p++;
	}
	return (size_t)-1;
}

/* Length of the longest suffix of buf that is a proper prefix of the
 * marker (a marker split across two reads). */
static size_t partial_marker_suffix(const RnBuf *b) {
	size_t max = b->len < RN_DONE_MARK_LEN - 1? b->len: RN_DONE_MARK_LEN - 1;
	size_t k;
	for (k = max; k > 0; k--) {
		if (!memcmp (b->data + b->len - k, RN_DONE_MARK, k)) {
			return k;
		}
	}
	return 0;
}

/* Hands out (or discards) buf[0, n) and erases it. */
static void take_segment(RnReader *r, size_t n, unsigned long id, RnBuf *out) {
	if (n == 0) {
		return;
	}
	bool mine = r->n_out == 0 || r->outstanding[0] >= id;
	if (mine && out) {
		rn_buf_append (out, r->buf.data, n);
	}
	rn_buf_consume (&r->buf, n);
}

static void pop_completed(RnReader *r, unsigned long mid) {
	size_t k = 0;
	while (k < r->n_out && r->outstanding[k] <= mid) {
		k++;
	}
	if (k) {
		memmove (r->outstanding, r->outstanding + k, (r->n_out - k) * sizeof (*r->outstanding));
		r->n_out -= k;
	}
}

/* Locates the first complete marker line. Returns false if there is none
 * yet, in which case *limit is how many leading bytes are certainly not
 * part of a marker. */
static bool next_marker(const RnBuf *b, size_t *pos, size_t *marker_len, unsigned long *mid, size_t *limit,
		unsigned long *pending) {
	size_t p = find_mark (b);
	const char *nl = NULL;
	if (p != (size_t)-1) {
		nl = memchr (b->data + p, '\n', b->len - p);
	}
	if (p == (size_t)-1 || !nl) {
		*limit = (p != (size_t)-1)? p: b->len - partial_marker_suffix (b);
		return false;
	}
	/* The buffer is NUL terminated and the id is followed by '\n', so
	 * strtoul cannot run past the marker line. */
	*mid = strtoul (b->data + p + RN_DONE_MARK_LEN, NULL, 10);
	*pos = p;
	if (pending) {
		/* optional " ev=<n>" field after the id */
		const char *q = b->data + p + RN_DONE_MARK_LEN;
		*pending = 0;
		for (; q + 4 < nl; q++) {
			if (!memcmp (q, " ev=", 4)) {
				*pending = strtoul (q + 4, NULL, 10);
				break;
			}
		}
	}
	/* Marker length is taken before the bytes in front of it are erased;
	 * computing it afterwards from the old offsets would eat the start
	 * of the next response. */
	*marker_len = (size_t)(nl - b->data) + 1 - p;
	return true;
}

bool rn_reader_poll(RnReader *r, unsigned long id, RnBuf *out) {
	for (;;) {
		size_t p = 0, marker_len = 0, limit = 0;
		unsigned long mid = 0, pending = 0;
		if (!next_marker (&r->buf, &p, &marker_len, &mid, &limit, &pending)) {
			take_segment (r, limit, id, out);
			return false;
		}
		take_segment (r, p, id, out);
		rn_buf_consume (&r->buf, marker_len);
		pop_completed (r, mid);
		if (mid == id) {
			r->pending_events = pending;
			return true;
		}
		/* marker of an abandoned request: keep going */
	}
}

void rn_reader_drain(RnReader *r, RnBuf *out) {
	for (;;) {
		size_t p = 0, marker_len = 0, limit = 0;
		unsigned long mid = 0;
		if (!next_marker (&r->buf, &p, &marker_len, &mid, &limit, NULL)) {
			if (out && limit) {
				rn_buf_append (out, r->buf.data, limit);
			}
			rn_buf_consume (&r->buf, limit);
			return;
		}
		if (out && p) {
			rn_buf_append (out, r->buf.data, p);
		}
		rn_buf_consume (&r->buf, p + marker_len);
		pop_completed (r, mid);
	}
}

/* ---- parsers ---- */

static int hexval(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

/* Parses hex digits in [p, end). Returns the first non-hex position; sets
 * *ok to false when there were no digits or more than 16. */
static const char *parse_hex64(const char *p, const char *end, uint64_t *out, bool *ok) {
	uint64_t v = 0;
	int n = 0;
	while (p < end && hexval (*p) >= 0) {
		if (n < 16) {
			v = (v << 4) | (uint64_t)hexval (*p);
		}
		n++;
		p++;
	}
	*ok = n > 0 && n <= 16;
	*out = v;
	return p;
}

int rn_parse_md(const char *resp, size_t resp_len, uint64_t addr, uint8_t *out, int max) {
	const char *p = resp;
	const char *end = resp + resp_len;
	int count = 0;
	bool have_dump = false;

	while (p < end) {
		const char *eol = memchr (p, '\n', (size_t)(end - p));
		const char *le = eol? eol: end;
		const char *q = p;
		p = eol? eol + 1: end;

		size_t ll = (size_t)(le - q);
		if (ll >= 12 && !memcmp (q, "Memory at 0x", 12)) {
			uint64_t haddr = 0;
			bool ok = false;
			parse_hex64 (q + 12, le, &haddr, &ok);
			if (ok && haddr == addr && count == 0) {
				have_dump = true;
			}
			continue;
		}
		if (ll < 4 || q[0] != '0' || (q[1] != 'x' && q[1] != 'X')) {
			continue;
		}
		uint64_t laddr = 0;
		bool ok = false;
		q = parse_hex64 (q + 2, le, &laddr, &ok);
		if (!ok || q >= le || *q != ':' || laddr != addr + (uint64_t)count) {
			continue;
		}
		q++;
		have_dump = true;
		while (count < max) {
			while (q < le && *q == ' ') {
				q++;
			}
			/* a byte is two hex digits followed by a blank; anything
			 * else (the "|ascii|" column, a truncated line) ends it */
			if (le - q < 3 || q[2] != ' ') {
				break;
			}
			int hi = hexval (q[0]);
			int lo = hexval (q[1]);
			if (hi < 0 || lo < 0) {
				break;
			}
			out[count++] = (uint8_t)((hi << 4) | lo);
			q += 3;
		}
	}
	return (have_dump && count > 0)? count: -1;
}

int rn_hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t max) {
	if (hex_len % 2 || hex_len / 2 > max || hex_len / 2 > (size_t)INT32_MAX) {
		return -1;
	}
	size_t i;
	for (i = 0; i < hex_len; i += 2) {
		int hi = hexval (hex[i]);
		int lo = hexval (hex[i + 1]);
		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i / 2] = (uint8_t)((hi << 4) | lo);
	}
	return (int)(hex_len / 2);
}

static const char *skip_blank(const char *p, const char *end) {
	while (p < end && (*p == ' ' || *p == '\t')) {
		p++;
	}
	return p;
}

static const char *skip_field(const char *p, const char *end) {
	while (p < end && *p != ' ' && *p != '\t') {
		p++;
	}
	return p;
}

bool rn_parse_maps_line(const char *line, size_t len, RnMapLine *out) {
	const char *p = line;
	const char *end = line + len;
	bool ok = false;

	while (end > p && (end[-1] == '\n' || end[-1] == '\r')) {
		end--;
	}
	memset (out, 0, sizeof (*out));
	p = parse_hex64 (p, end, &out->start, &ok);
	if (!ok || p >= end || *p != '-') {
		return false;
	}
	p = parse_hex64 (p + 1, end, &out->end, &ok);
	if (!ok || p >= end || *p != ' ' || out->end <= out->start) {
		return false;
	}
	p = skip_blank (p, end);
	const char *f = skip_field (p, end);
	if (f - p != 4) {
		return false;
	}
	memcpy (out->perms, p, 4);
	p = skip_blank (f, end);
	p = parse_hex64 (p, end, &out->offset, &ok);
	if (!ok) {
		return false;
	}
	p = skip_blank (p, end);
	p = skip_field (p, end);       /* dev */
	p = skip_blank (p, end);
	p = skip_field (p, end);       /* inode */
	p = skip_blank (p, end);
	size_t pl = (size_t)(end - p);
	if (pl >= sizeof (out->path)) {
		pl = sizeof (out->path) - 1;
	}
	memcpy (out->path, p, pl);
	out->path[pl] = '\0';
	return true;
}

/* ---- URI ---- */

static bool copy_token(char *dst, size_t dst_size, const char *src, size_t n) {
	if (n == 0 || n >= dst_size) {
		return false;
	}
	memcpy (dst, src, n);
	dst[n] = '\0';
	return true;
}

static bool valid_port(const char *s) {
	if (!*s || strlen (s) > 5) {
		return false;
	}
	const char *p;
	for (p = s; *p; p++) {
		if (*p < '0' || *p > '9') {
			return false;
		}
	}
	long v = strtol (s, NULL, 10);
	return v > 0 && v <= 65535;
}

static bool valid_target(const char *s, bool spawn) {
	const char *p;
	if (!*s) {
		return false;
	}
	for (p = s; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (spawn) {
			/* package[/activity] characters only: this string is
			 * pasted into a line of the command protocol */
			bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
				|| (c >= '0' && c <= '9') || c == '.' || c == '_'
				|| c == '-' || c == ':' || c == '$';
			if (!ok) {
				return false;
			}
		} else if (c < '0' || c > '9') {
			return false;
		}
	}
	return true;
}

bool rn_parse_uri(const char *uri, const char *def_host, const char *def_port, RnUri *out, const char **err) {
	static const char pfx[] = "renef://";
	const char *e = "invalid URI, expected renef://[host[:port]/]<spawn|attach>/<target>";
	const char *p = uri;

	memset (out, 0, sizeof (*out));
	if (err) {
		*err = e;
	}
	if (!strncmp (p, pfx, sizeof (pfx) - 1)) {
		p += sizeof (pfx) - 1;
	}
	const char *slash = strchr (p, '/');
	if (!slash) {
		return false;
	}
	size_t n = (size_t)(slash - p);
	bool is_spawn = n == 5 && !strncmp (p, "spawn", 5);
	bool is_attach = n == 6 && !strncmp (p, "attach", 6);
	const char *host = def_host;
	const char *port = def_port;
	char hostbuf[sizeof (out->host)];
	char portbuf[sizeof (out->port)];

	if (!is_spawn && !is_attach) {
		/* authority component: host, host:port, [v6] or [v6]:port */
		const char *h = p;
		const char *hend = slash;
		const char *colon = NULL;
		if (*h == '[') {
			const char *rb = memchr (h, ']', n);
			if (!rb) {
				return false;
			}
			if (rb + 1 < slash) {
				if (rb[1] != ':') {
					return false;
				}
				colon = rb + 1;
			}
			h++;
			hend = rb;
		} else {
			colon = memchr (h, ':', n);
			if (colon) {
				hend = colon;
			}
		}
		if (!copy_token (hostbuf, sizeof (hostbuf), h, (size_t)(hend - h))) {
			return false;
		}
		host = hostbuf;
		if (colon) {
			if (!copy_token (portbuf, sizeof (portbuf), colon + 1, (size_t)(slash - colon - 1))) {
				if (err) {
					*err = "invalid port in URI";
				}
				return false;
			}
			port = portbuf;
		}
		p = slash + 1;
		slash = strchr (p, '/');
		if (!slash) {
			return false;
		}
		n = (size_t)(slash - p);
		is_spawn = n == 5 && !strncmp (p, "spawn", 5);
		is_attach = n == 6 && !strncmp (p, "attach", 6);
		if (!is_spawn && !is_attach) {
			return false;
		}
	}
	if (!host || !port || !valid_port (port)) {
		if (err) {
			*err = "invalid port";
		}
		return false;
	}
	if (strlen (host) >= sizeof (out->host)) {
		return false;
	}
	strcpy (out->host, host);
	strcpy (out->port, port);
	out->spawn = is_spawn;
	const char *t = slash + 1;
	size_t tl = strlen (t);
	while (tl > 0 && t[tl - 1] == '/') {
		tl--;
	}
	if (!copy_token (out->target, sizeof (out->target), t, tl) || !valid_target (out->target, is_spawn)) {
		if (err) {
			*err = is_spawn? "invalid package name": "invalid pid";
		}
		return false;
	}
	if (err) {
		*err = NULL;
	}
	return true;
}

/* ---- Lua helpers ---- */

bool rn_lua_quote(RnBuf *out, const char *s, size_t len) {
	size_t i;
	if (!rn_buf_append (out, "\"", 1)) {
		return false;
	}
	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)s[i];
		bool ok;
		if (c == '"' || c == '\\') {
			char esc[2] = { '\\', (char)c };
			ok = rn_buf_append (out, esc, 2);
		} else if (c < 0x20 || c >= 0x7f || (c == '/' && i > 0 && s[i - 1] == '/')) {
			/* three decimal digits: unambiguous whatever follows */
			ok = rn_buf_appendf (out, "\\%03u", (unsigned)c);
		} else {
			ok = rn_buf_append (out, &s[i], 1);
		}
		if (!ok) {
			return false;
		}
	}
	return rn_buf_append (out, "\"", 1);
}

bool rn_hex_encode(RnBuf *out, const void *data, size_t len) {
	static const char digits[] = "0123456789abcdef";
	const unsigned char *d = data;
	char tmp[512];
	size_t i = 0;
	while (i < len) {
		size_t n = 0;
		while (i < len && n + 2 <= sizeof (tmp)) {
			tmp[n++] = digits[d[i] >> 4];
			tmp[n++] = digits[d[i] & 15];
			i++;
		}
		if (!rn_buf_append (out, tmp, n)) {
			return false;
		}
	}
	return true;
}

bool rn_lua_wrap_script(RnBuf *out, const char *script, size_t len, const char *chunkname) {
	return rn_buf_puts (out, "local f,e=load((\"")
		&& rn_hex_encode (out, script, len)
		&& rn_buf_puts (out, "\"):gsub('%x%x',function(h) return string.char(tonumber(h,16)) end),")
		&& rn_lua_quote (out, chunkname, strlen (chunkname))
		&& rn_buf_puts (out, ") if not f then print('ERROR: '..tostring(e)) else"
			" local ok,e2=pcall(f) if not ok then print('ERROR: '..tostring(e2)) end end");
}

bool rn_base64_encode(RnBuf *out, const void *data, size_t len) {
	static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const unsigned char *d = data;
	size_t i;
	for (i = 0; i < len; i += 3) {
		unsigned v = (unsigned)d[i] << 16;
		char q[4];
		if (i + 1 < len) {
			v |= (unsigned)d[i + 1] << 8;
		}
		if (i + 2 < len) {
			v |= d[i + 2];
		}
		q[0] = tbl[(v >> 18) & 63];
		q[1] = tbl[(v >> 12) & 63];
		q[2] = (i + 1 < len)? tbl[(v >> 6) & 63]: '=';
		q[3] = (i + 2 < len)? tbl[v & 63]: '=';
		if (!rn_buf_append (out, q, 4)) {
			return false;
		}
	}
	return true;
}

char *rn_search_pattern(const char *in, size_t len, bool is_hex) {
	RnBuf o;
	size_t i = 0;
	int count = 0;
	rn_buf_init (&o);

	if (!is_hex) {
		if (len == 0 || len > 256) {
			return NULL;
		}
		for (i = 0; i < len; i++) {
			if (!rn_buf_appendf (&o, "%02X ", (unsigned)(unsigned char)in[i])) {
				goto fail;
			}
		}
		return rn_buf_steal (&o, NULL);
	}
	while (i < len) {
		if (in[i] == ' ' || in[i] == '\t') {
			i++;
			continue;
		}
		if (i + 1 >= len || count >= 256) {
			goto fail;
		}
		if ((in[i] == '?' && in[i + 1] == '?') || (in[i] == '.' && in[i + 1] == '.')) {
			if (!rn_buf_puts (&o, "?? ")) {
				goto fail;
			}
		} else {
			int hi = hexval (in[i]);
			int lo = hexval (in[i + 1]);
			if (hi < 0 || lo < 0 || !rn_buf_appendf (&o, "%02X ", (unsigned)((hi << 4) | lo))) {
				goto fail;
			}
		}
		count++;
		i += 2;
	}
	if (count == 0) {
		goto fail;
	}
	return rn_buf_steal (&o, NULL);
fail:
	rn_buf_fini (&o);
	return NULL;
}
