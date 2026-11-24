/* r2renef - MIT - Copyright 2025-2026 */

#include "renef_memory.h"
#include "renef_session.h"
#include "renef_maps.h"

/*
 * Reading target memory
 *
 * `md <addr> <size>` is the only read primitive every renef_server has.
 * It is safe on unmapped addresses (the agent guards the copy), but it
 * answers with an ASCII dump of about five characters per byte and at most
 * 4096 bytes per request.
 *
 * The Lua path below asks for plain hex (two characters per byte, up to
 * RN_LUA_READ_MAX bytes per request). Memory.read() itself dereferences
 * the address without any guard, so the snippet first walks
 * /proc/self/maps and reads only the leading part of the range that is
 * mapped readable. Until one result has been compared with md it is not
 * trusted (RENEF_READ=auto), and it is dropped for the session if it
 * ever fails to answer.
 */

static const char LUA_READ[] =
	"local a,n=0x%" PFMT64x ",%d local c,e=a,a+n "
	"local f=io.open('/proc/self/maps','r') "
	"if not f then print('" RN_TAG "Q') return end "
	"for l in f:lines() do local s,t,p=l:match('^(%%x+)-(%%x+) (%%S+)') "
	"if s then s=tonumber(s,16) t=tonumber(t,16) "
	"if t>c then if s>c or p:sub(1,1)~='r' then break end c=t if c>=e then break end end end end "
	"f:close() if c>e then c=e end "
	"if c<=a then print('" RN_TAG "E') return end "
	"if not __r2h then local h={} for i=0,255 do h[string.char(i)]=string.format('%%02x',i) end __r2h=h end "
	"print('" RN_TAG "H'..string.format('%%x',a)..':'..(Memory.read(a,c-a):gsub('.',__r2h)))";

/* Memory.write() is a bare memcpy and Memory.patch() makes the pages RWX
 * first (and leaves them so). Use the former only where every page is
 * already writable, and refuse ranges that are not mapped at all: writing
 * there would kill the target. */
static const char LUA_WRITE_HEAD[] =
	"local a,n=0x%" PFMT64x ",%d local d=\"";
static const char LUA_WRITE_TAIL[] =
	"\" local c,e,w=a,a+n,true "
	"local f=io.open('/proc/self/maps','r') "
	"if f then for l in f:lines() do local s,t,p=l:match('^(%x+)-(%x+) (%S+)') "
	"if s then s=tonumber(s,16) t=tonumber(t,16) "
	"if t>c then if s>c then break end if p:sub(2,2)~='w' then w=false end c=t if c>=e then break end end end end "
	"f:close() if c<e then print('" RN_TAG "E address range is not mapped') return end "
	"else w=false end "
	"local ok,err if w then ok,err=pcall(Memory.write,a,d) else ok,err=Memory.patch(a,d) end "
	"if ok then print('" RN_TAG "W'..n) else print('" RN_TAG "E '..tostring(err)) end";

/* addresses the Lua snippets can compare (Lua integers are signed) */
#define RN_LUA_ADDR_MAX ((ut64)0x7fffffffffffffffULL)

/* Every exec costs a public (unframed) renef_server five seconds: its
 * exec handler waits for a completion text the agent never sends and only
 * returns after that much silence. md has no such wait, so the Lua path
 * is only chosen on its own for framed connections. */
static bool lua_path_wanted(RenefSession *s) {
	if (s->read_path == RN_READ_MD || !s->lua_read_ok) {
		return false;
	}
	return s->conn.framed || s->read_path == RN_READ_LUA;
}

const char *rn_read_path_name(RenefSession *s) {
	return lua_path_wanted (s)? "lua": "md";
}

/* ---- page cache ---- */

static RnPage *cache_slot(RenefSession *s, ut64 base) {
	return &s->cache[(base / RN_PAGE_SIZE) % RN_CACHE_PAGES];
}

static bool cache_fresh(RenefSession *s, ut64 base, long long now) {
	RnPage *pg = cache_slot (s, base);
	return pg->used && pg->base == base && s->cache_ttl_ms > 0
		&& now - pg->stamp < s->cache_ttl_ms;
}

static void cache_store(RenefSession *s, ut64 base, const ut8 *data, int len, long long now) {
	RnPage *pg = cache_slot (s, base);
	pg->used = true;
	pg->base = base;
	pg->len = len > 0? len: 0;
	pg->stamp = now;
	if (len > 0) {
		memcpy (pg->data, data, (size_t)len);
	}
}

/* ---- fetching ---- */

/* Bytes read (1..n), -1 if the server says the range cannot be read,
 * -2 if the request itself failed. */
static int md_read(RenefSession *s, ut64 addr, int n, ut8 *out) {
	char cmd[64];
	RnBuf reply;
	rn_buf_init (&reply);
	snprintf (cmd, sizeof (cmd), "md 0x%" PFMT64x " %d", addr, n);
	RnStatus st = rn_conn_request (&s->conn, cmd, strlen (cmd), RN_END_MD, 0, &reply);
	int got = -2;
	if (st == RN_OK) {
		got = rn_parse_md (reply.data? reply.data: "", reply.len, addr, out, n);
		s->n_md_reads++;
	} else {
		R_LOG_ERROR ("renef: md 0x%" PFMT64x ": %s", addr, rn_status_str (st));
	}
	rn_buf_fini (&reply);
	return got;
}

typedef struct {
	ut64 addr;
	ut8 *out;
	int max;
	int got;       /* -3 no answer, -2 malformed, -1 unreadable, >= 0 bytes */
	bool no_maps;
} LuaReadCtx;

static void lua_read_line(void *user, const char *line, size_t len) {
	LuaReadCtx *ctx = user;
	if (len == 1 && line[0] == 'E') {
		ctx->got = -1;
	} else if (len == 1 && line[0] == 'Q') {
		ctx->no_maps = true;
	} else if (len > 2 && line[0] == 'H') {
		const char *colon = memchr (line, ':', len);
		if (!colon) {
			ctx->got = -2;
			return;
		}
		/* the address is echoed, so a stale reply is never taken for
		 * the answer to this request */
		char abuf[20];
		size_t al = (size_t)(colon - line - 1);
		if (al == 0 || al >= sizeof (abuf)) {
			ctx->got = -2;
			return;
		}
		memcpy (abuf, line + 1, al);
		abuf[al] = '\0';
		if (strtoull (abuf, NULL, 16) != ctx->addr) {
			return;
		}
		size_t hl = len - (size_t)(colon + 1 - line);
		int n = rn_hex_decode (colon + 1, hl, ctx->out, (size_t)ctx->max);
		ctx->got = n > 0? n: -2;
	}
}

/* Bytes read (a prefix of the range), -1 unreadable, -2 the Lua path did
 * not produce a usable answer, -3 the request failed. */
static int lua_read(RenefSession *s, ut64 addr, int n, ut8 *out) {
	RnBuf reply;
	LuaReadCtx ctx = { addr, out, n, -3, false };
	char *lua = r_str_newf (LUA_READ, addr, n);
	if (!lua) {
		return -3;
	}
	rn_buf_init (&reply);
	RnStatus st = rn_exec (s, lua, 0, &reply);
	free (lua);
	if (st != RN_OK) {
		R_LOG_ERROR ("renef: read 0x%" PFMT64x ": %s", addr, rn_status_str (st));
		rn_buf_fini (&reply);
		return -3;
	}
	rn_scan_reply (s, &reply, lua_read_line, &ctx, NULL, NULL);
	rn_buf_fini (&reply);
	s->n_lua_reads++;
	if (ctx.no_maps || ctx.got == -3) {
		return -2;
	}
	return ctx.got;
}

/*
 * Execute-only code (--x: no read permission) cannot be read from inside
 * the target: both md and Memory.read() run there and would fault. A
 * renef_server that has `memdump <pid> <start>-<end>` reads the range from
 * /proc/<pid>/mem instead, which the kernel allows for a privileged reader
 * whatever the page protection is. Reply:
 *
 *   MEMDUMP_MANIFEST ...
 *   SEG OK start=0x<addr> len=<n> hex=<2n hex chars>
 *   SEG ERR start=0x<addr> len=<n> ...
 *   MEMDUMP_SUMMARY ... / MEMDUMP_END
 *
 * Only tried on framed connections: an unframed (public) server has no
 * such command and no cheap way to say so.
 */
static bool proc_read_possible(RenefSession *s) {
	return s->conn.framed && s->memdump_cmd >= 0 && s->pid > 0;
}

/* Bytes read (a prefix of the range), -1 unreadable or not supported,
 * -2 the request failed. */
static int proc_read(RenefSession *s, ut64 addr, int n, ut8 *out) {
	static const char SEG_OK[] = "SEG OK start=0x";
	char cmd[96];
	RnBuf reply;
	if (!proc_read_possible (s)) {
		return -1;
	}
	rn_buf_init (&reply);
	snprintf (cmd, sizeof (cmd), "memdump %d %" PFMT64x "-%" PFMT64x, s->pid, addr, addr + (ut64)n);
	RnStatus st = rn_conn_request (&s->conn, cmd, strlen (cmd), RN_END_QUIET, 0, &reply);
	if (st != RN_OK) {
		R_LOG_ERROR ("renef: memdump 0x%" PFMT64x ": %s", addr, rn_status_str (st));
		rn_buf_fini (&reply);
		return -2;
	}
	const char *p = reply.data? reply.data: "";
	const char *end = p + reply.len;
	bool known = false;
	int got = 0;
	while (p < end) {
		const char *nl = memchr (p, '\n', (size_t)(end - p));
		const char *le = nl? nl: end;
		size_t ll = (size_t)(le - p);
		if (ll >= 8 && !memcmp (p, "MEMDUMP_", 8)) {
			known = true;
		} else if (ll > sizeof (SEG_OK) - 1 && !memcmp (p, SEG_OK, sizeof (SEG_OK) - 1)) {
			char *q = NULL;
			ut64 sa = strtoull (p + sizeof (SEG_OK) - 1, &q, 16);
			const char *hex = NULL;
			const char *k;
			for (k = q; k && k + 4 < le; k++) {
				if (!memcmp (k, "hex=", 4)) {
					hex = k + 4;
					break;
				}
			}
			/* segments arrive in address order; only a gapless prefix counts */
			if (hex && sa == addr + (ut64)got && got < n) {
				int d = rn_hex_decode (hex, (size_t)(le - hex), out + got, (size_t)(n - got));
				if (d > 0) {
					got += d;
				}
			}
		}
		p = nl? nl + 1: end;
	}
	rn_buf_fini (&reply);
	if (!known) {
		/* "ERROR: Unknown command": this server cannot do it */
		s->memdump_cmd = -1;
		return -1;
	}
	s->memdump_cmd = 1;
	s->n_proc_reads++;
	return got > 0? got: -1;
}

/* true if the page at `pb` lies in a mapping the target itself cannot read
 * but can execute */
static bool page_exec_only(RenefSession *s, ut64 pb) {
	if (s->modlist_only || !s->n_ranges) {
		return false;
	}
	const RnRange *r = rn_range_at (s, pb);
	return r && r->perms[0] != 'r' && r->perms[2] == 'x';
}

static void lua_path_off(RenefSession *s, const char *why) {
	if (s->lua_read_ok) {
		s->lua_read_ok = false;
		s->lua_read_checked = true;
		R_LOG_WARN ("renef: Lua read path disabled (%s), using md", why);
	}
}

static void store_run(RenefSession *s, ut64 base, int npages, const ut8 *data, int got, long long now) {
	int i;
	for (i = 0; i < npages; i++) {
		int len = got - i * RN_PAGE_SIZE;
		if (len > RN_PAGE_SIZE) {
			len = RN_PAGE_SIZE;
		}
		cache_store (s, base + (ut64)i * RN_PAGE_SIZE, len > 0? data + (size_t)i * RN_PAGE_SIZE: NULL, len, now);
	}
}

/* true if [from, to) touches a known range of the target */
static bool range_overlaps(RenefSession *s, ut64 from, ut64 to) {
	size_t lo = 0, hi = s->n_ranges;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const RnRange *r = &s->ranges[mid];
		if (to <= r->start) {
			hi = mid;
		} else if (from >= r->end) {
			lo = mid + 1;
		} else {
			return true;
		}
	}
	return false;
}

/* Fetches `npages` consecutive pages starting at `base` into the cache,
 * through the agent (Lua or md). */
static void fetch_run_agent(RenefSession *s, ut64 base, int npages, ut8 *tmp) {
	long long now = rn_now_ms ();
	int i;

	if (base < RN_PAGE_SIZE) {
		/* the zero page is never mapped; radare2 probes it on open */
		cache_store (s, base, NULL, 0, now);
		base += RN_PAGE_SIZE;
		if (--npages == 0) {
			return;
		}
	}
	if (s->maps_mode == RN_MAPS_RANGES && s->maps_applied && !s->modlist_only) {
		/* radare2 only reads through the io maps made from the target's
		 * ranges, except when it probes the descriptor itself (file type
		 * detection on open). Nothing is mapped outside those ranges, so
		 * such reads need no round trip. */
		while (npages > 0 && !range_overlaps (s, base, base + RN_PAGE_SIZE)) {
			cache_store (s, base, NULL, 0, now);
			base += RN_PAGE_SIZE;
			npages--;
		}
		int keep = 0;
		while (keep < npages && range_overlaps (s, base + (ut64)keep * RN_PAGE_SIZE,
				base + (ut64)(keep + 1) * RN_PAGE_SIZE)) {
			keep++;
		}
		for (i = keep; i < npages; i++) {
			cache_store (s, base + (ut64)i * RN_PAGE_SIZE, NULL, 0, now);
		}
		npages = keep;
		if (npages == 0) {
			return;
		}
	}
	ut64 last = base + (ut64)npages * RN_PAGE_SIZE - 1;
	bool lua_ok = lua_path_wanted (s) && last >= base && last < RN_LUA_ADDR_MAX;

	if (lua_ok && !s->lua_read_checked) {
		/* Not trusted yet: md decides what the first page holds, and
		 * the Lua path earns its keep by reproducing it. */
		ut8 ref[RN_PAGE_SIZE];
		int mgot = md_read (s, base, RN_PAGE_SIZE, ref);
		if (mgot == -2) {
			return;
		}
		cache_store (s, base, ref, mgot, now);
		if (mgot == RN_PAGE_SIZE) {
			int lgot = lua_read (s, base, RN_PAGE_SIZE, tmp);
			if (lgot == -2) {
				lua_path_off (s, "no usable answer");
			} else if (lgot == RN_PAGE_SIZE && !memcmp (ref, tmp, RN_PAGE_SIZE)) {
				s->lua_read_checked = true;
			} else if (lgot != -3 && ++s->lua_read_strikes >= 3) {
				/* a page that changes between the two reads can
				 * differ once; three times is the path's fault */
				lua_path_off (s, "result differs from md");
			}
		}
		base += RN_PAGE_SIZE;
		if (--npages == 0) {
			return;
		}
		lua_ok = s->lua_read_ok && s->lua_read_checked;
	}
	if (lua_ok) {
		int got = lua_read (s, base, npages * RN_PAGE_SIZE, tmp);
		if (got == -3) {
			return;
		}
		if (got != -2) {
			store_run (s, base, npages, tmp, got, now);
			return;
		}
		lua_path_off (s, "no usable answer");
	}
	for (i = 0; i < npages; i++) {
		ut64 pb = base + (ut64)i * RN_PAGE_SIZE;
		int got = md_read (s, pb, RN_PAGE_SIZE, tmp);
		if (got == -2) {
			return;
		}
		cache_store (s, pb, tmp, got, now);
	}
}

/* Fetches `npages` consecutive pages starting at `base` into the cache.
 * Stretches of execute-only pages go to the server's /proc/<pid>/mem
 * reader, everything else to the agent. */
static void fetch_run(RenefSession *s, ut64 base, int npages, ut8 *tmp) {
	int i = 0;
	while (i < npages) {
		ut64 pb = base + (ut64)i * RN_PAGE_SIZE;
		bool xo = proc_read_possible (s) && page_exec_only (s, pb);
		int j = i + 1;
		while (j < npages && (proc_read_possible (s)
				&& page_exec_only (s, base + (ut64)j * RN_PAGE_SIZE)) == xo) {
			j++;
		}
		if (xo) {
			int got = proc_read (s, pb, (j - i) * RN_PAGE_SIZE, tmp);
			if (got == -2) {
				return;
			}
			if (got > 0) {
				store_run (s, pb, j - i, tmp, got, rn_now_ms ());
				i = j;
				continue;
			}
			if (proc_read_possible (s)) {
				/* supported, but these pages cannot be read at all */
				store_run (s, pb, j - i, tmp, 0, rn_now_ms ());
				i = j;
				continue;
			}
			/* the server turned out not to have the command */
		}
		fetch_run_agent (s, pb, j - i, tmp);
		i = j;
	}
}

static void cache_fill(RenefSession *s, ut64 base, int npages, ut8 *tmp) {
	long long now = rn_now_ms ();
	int i = 0;
	while (i < npages) {
		if (cache_fresh (s, base + (ut64)i * RN_PAGE_SIZE, now)) {
			i++;
			continue;
		}
		int j = i;
		while (j < npages && !cache_fresh (s, base + (ut64)j * RN_PAGE_SIZE, now)) {
			j++;
		}
		fetch_run (s, base + (ut64)i * RN_PAGE_SIZE, j - i, tmp);
		i = j;
	}
}

/* ---- IO callbacks ---- */

int renef_read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
	RenefSession *s = desc? desc->data: NULL;
	const int window = RN_LUA_READ_MAX / RN_PAGE_SIZE;
	if (!s || !buf || count < 1) {
		return -1;
	}
	ut8 *tmp = malloc (RN_LUA_READ_MAX);
	if (!tmp) {
		return -1;
	}
	const ut64 addr = s->off;
	int done = 0;
	bool stop = false;

	rn_conn_lock (&s->conn);
	while (done < count && !stop && rn_conn_is_open (&s->conn)) {
		ut64 a = addr + (ut64)done;
		if (a < addr) {
			break;  /* wrapped past the end of the address space */
		}
		ut64 wbase = a & RN_PAGE_MASK;
		ut64 need = (a - wbase) + (ut64)(count - done);
		int np = need > (ut64)RN_LUA_READ_MAX? window: (int)((need + RN_PAGE_SIZE - 1) / RN_PAGE_SIZE);
		while (np > 1 && wbase + (ut64)np * RN_PAGE_SIZE - 1 < wbase) {
			np--;
		}
		cache_fill (s, wbase, np, tmp);
		int k;
		for (k = 0; k < np && done < count; k++) {
			ut64 pb = wbase + (ut64)k * RN_PAGE_SIZE;
			RnPage *pg = cache_slot (s, pb);
			a = addr + (ut64)done;
			int po = (int)(a - pb);
			if (!pg->used || pg->base != pb || pg->len <= po) {
				stop = true;
				break;
			}
			int n = pg->len - po;
			if (n > count - done) {
				n = count - done;
			}
			memcpy (buf + done, pg->data + po, (size_t)n);
			done += n;
			if (pg->len < RN_PAGE_SIZE) {
				stop = true;
			}
		}
	}
	rn_conn_unlock (&s->conn);
	free (tmp);
	if (done < count) {
		memset (buf + done, io? io->Oxff: 0xff, (size_t)(count - done));
	}
	return done;
}

typedef struct {
	bool ok;
	char err[160];
} WriteCtx;

static void write_line(void *user, const char *line, size_t len) {
	WriteCtx *ctx = user;
	if (len >= 1 && line[0] == 'W') {
		ctx->ok = true;
	} else if (len >= 1 && line[0] == 'E') {
		line++;
		len--;
		while (len && *line == ' ') {
			line++;
			len--;
		}
		size_t n = len < sizeof (ctx->err) - 1? len: sizeof (ctx->err) - 1;
		memcpy (ctx->err, line, n);
		ctx->err[n] = '\0';
	}
}

int renef_write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
	RenefSession *s = desc? desc->data: NULL;
	if (!s || !buf || count < 1) {
		return -1;
	}
	const ut64 addr = s->off;
	int done = 0;

	if (addr > RN_LUA_ADDR_MAX || (ut64)count > RN_LUA_ADDR_MAX - addr) {
		R_LOG_ERROR ("renef: write 0x%" PFMT64x ": address out of range", addr);
		return -1;
	}
	while (done < count) {
		int n = count - done;
		if (n > RN_WRITE_CHUNK) {
			n = RN_WRITE_CHUNK;
		}
		RnBuf lua, reply;
		WriteCtx ctx = { false, "" };
		bool built;
		int i;
		rn_buf_init (&lua);
		rn_buf_init (&reply);
		built = rn_buf_appendf (&lua, LUA_WRITE_HEAD, addr + (ut64)done, n);
		for (i = 0; built && i < n; i++) {
			built = rn_buf_appendf (&lua, "\\x%02x", buf[done + i]);
		}
		built = built && rn_buf_puts (&lua, LUA_WRITE_TAIL);
		RnStatus st = built? rn_exec (s, lua.data, 0, &reply): RN_ERROR;
		if (st == RN_OK) {
			rn_scan_reply (s, &reply, write_line, &ctx, NULL, NULL);
		}
		rn_buf_fini (&lua);
		rn_buf_fini (&reply);
		if (st != RN_OK || !ctx.ok) {
			R_LOG_ERROR ("renef: write 0x%" PFMT64x " failed: %s", addr + (ut64)done,
				st != RN_OK? rn_status_str (st): (*ctx.err? ctx.err: "no confirmation from target"));
			break;
		}
		done += n;
	}
	rn_cache_flush (s);
	return done > 0? done: -1;
}

ut64 renef_lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
	RenefSession *s = desc? desc->data: NULL;
	if (!s) {
		return UT64_MAX;
	}
	switch (whence) {
	case R_IO_SEEK_SET:
		s->off = offset;
		break;
	case R_IO_SEEK_CUR:
		s->off += offset;
		break;
	case R_IO_SEEK_END:
		/* The descriptor is a whole address space, not a file: its
		 * "size" is the top of that space, as for ptrace:// & co. */
		s->off = UT64_MAX;
		break;
	}
	return s->off;
}
