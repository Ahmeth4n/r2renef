/* r2renef - MIT - Copyright 2025-2026 */

#include "renef_maps.h"
#include "renef_session.h"

/*
 * The target's memory map is read from /proc/self/maps through Lua's io
 * library (the agent opens the standard libraries), which is the only
 * source that lists every range with its permissions. Module.list() is
 * the fallback: it returns the same line format but only the first
 * mapping of each library.
 *
 * Renef builds with request framing send print() through a bounded queue
 * in the agent (256KB, oldest dropped first), so there a listing is
 * fetched in pages of about 100KB. Public builds write directly and have
 * no such limit - but hold the server for five seconds after every exec -
 * so there the whole listing is asked for at once. Should an agent
 * announce dropped output anyway, the listing is fetched again in pages.
 */
#define RN_PAGE_LINES 400
#define RN_PAGE_BYTES 100000
#define RN_UNPAGED 1000000000

static int page_lines(RenefSession *s) {
	return s->paged? RN_PAGE_LINES: RN_UNPAGED;
}

static int page_bytes(RenefSession *s) {
	return s->paged? RN_PAGE_BYTES: RN_UNPAGED;
}

/* the agent's notice that its output queue overflowed */
static bool reply_dropped(const RnBuf *reply) {
	return reply->data && strstr (reply->data, "[dropped ") != NULL;
}

static const char LUA_MAPS[] =
	"local i,from,o,z,more=0,%ld,{},0,0 "
	"local f=io.open('/proc/self/maps','r') "
	"if f then for l in f:lines() do if i>=from then "
	"if #o>=%d or z>%d then more=1 break end "
	"o[#o+1]='" RN_TAG "M'..l z=z+#l end i=i+1 end f:close() "
	"o[#o+1]='" RN_TAG "N'..i..' '..more "
	"else local m=Module.list() if type(m)=='string' then for l in m:gmatch('[^\\n]+') do o[#o+1]='" RN_TAG "M'..l end end "
	"o[#o+1]='" RN_TAG "L' end "
	"print(table.concat(o,'\\n'))";

/* %s: quoted library name, %ld: first index, %d: 0 exports / 1 symbols,
 * %s: Module function, %d %d: page limits. The table is kept in a global
 * between pages so a big library is parsed once, not once per page. */
static const char LUA_SYMS[] =
	"local L,from,k=%s,%ld,%d "
	"if from==1 or not __r2e or __r2e.l~=L or __r2e.k~=k then __r2e={l=L,k=k,t=Module.%s(L),b=Module.find(L)} end "
	"local t=__r2e.t if not t then __r2e=nil print('" RN_TAG "E no symbol table for '..L) return end "
	"local o,z,i={},0,from while i<=#t and #o<%d and z<%d do local n=tostring(t[i].name) "
	"o[#o+1]='" RN_TAG "X'..string.format('%%x',t[i].offset)..' '..n z=z+#n+24 i=i+1 end "
	"o[#o+1]='" RN_TAG "N'..#t..' '..i..' '..string.format('%%x',__r2e.b or 0) "
	"if i>#t then __r2e=nil end print(table.concat(o,'\\n'))";

#define RN_MAX_PAGES 2000

/* ---- ranges ---- */

typedef struct {
	RnRange *v;
	size_t n;
	size_t cap;
	long next;
	int more;
	bool got_end;
	bool modlist;
	bool oom;
} MapsCtx;

static void maps_line(void *user, const char *line, size_t len) {
	MapsCtx *ctx = user;
	if (len < 1) {
		return;
	}
	if (line[0] == 'L') {
		ctx->modlist = true;
		ctx->got_end = true;
		ctx->more = 0;
	} else if (line[0] == 'N') {
		char tmp[48];
		size_t n = len - 1 < sizeof (tmp) - 1? len - 1: sizeof (tmp) - 1;
		memcpy (tmp, line + 1, n);
		tmp[n] = '\0';
		if (sscanf (tmp, "%ld %d", &ctx->next, &ctx->more) == 2) {
			ctx->got_end = true;
		}
	} else if (line[0] == 'M') {
		RnMapLine ml;
		if (!rn_parse_maps_line (line + 1, len - 1, &ml)) {
			return;
		}
		/* pages are fetched one request apart: drop what a changed
		 * map made overlap */
		if (ctx->n && ml.start < ctx->v[ctx->n - 1].end) {
			return;
		}
		if (ctx->n == ctx->cap) {
			size_t ncap = ctx->cap? ctx->cap * 2: 512;
			RnRange *nv = realloc (ctx->v, ncap * sizeof (RnRange));
			if (!nv) {
				ctx->oom = true;
				return;
			}
			ctx->v = nv;
			ctx->cap = ncap;
		}
		RnRange *r = &ctx->v[ctx->n];
		r->start = ml.start;
		r->end = ml.end;
		r->offset = ml.offset;
		memcpy (r->perms, ml.perms, sizeof (r->perms));
		r->path = strdup (ml.path);
		if (!r->path) {
			ctx->oom = true;
			return;
		}
		ctx->n++;
	}
}

static void free_ranges(RnRange *v, size_t n) {
	size_t i;
	for (i = 0; i < n; i++) {
		free (v[i].path);
	}
	free (v);
}

static void free_modules(RenefSession *s) {
	size_t i;
	for (i = 0; i < s->n_modules; i++) {
		free (s->modules[i].name);
		free (s->modules[i].path);
	}
	free (s->modules);
	s->modules = NULL;
	s->n_modules = 0;
}

static bool is_module_path(const char *path) {
	if (path[0] != '/' || !strncmp (path, "/dev/", 5) || !strncmp (path, "/memfd:", 7)) {
		return false;
	}
	const char *base = strrchr (path, '/') + 1;
	if (strstr (base, ".so")) {
		return true;
	}
	return !strcmp (base, "linker64") || !strcmp (base, "linker") || !strncmp (base, "app_process", 11);
}

static int module_cmp(const void *a, const void *b) {
	const RnModule *ma = a, *mb = b;
	return ma->base < mb->base? -1: (ma->base > mb->base? 1: 0);
}

static bool build_modules(RenefSession *s) {
	size_t i, j, cap = 0;
	free_modules (s);
	for (i = 0; i < s->n_ranges; i++) {
		RnRange *r = &s->ranges[i];
		if (!is_module_path (r->path)) {
			continue;
		}
		RnModule *m = NULL;
		/* the mappings of one file are next to each other */
		for (j = s->n_modules; j > 0; j--) {
			if (!strcmp (s->modules[j - 1].path, r->path)) {
				m = &s->modules[j - 1];
				break;
			}
		}
		if (!m) {
			if (s->n_modules == cap) {
				size_t ncap = cap? cap * 2: 128;
				RnModule *nm = realloc (s->modules, ncap * sizeof (RnModule));
				if (!nm) {
					return false;
				}
				s->modules = nm;
				cap = ncap;
			}
			m = &s->modules[s->n_modules];
			memset (m, 0, sizeof (*m));
			m->path = strdup (r->path);
			const char *base = strrchr (r->path, '/') + 1;
			m->name = strdup (base);
			if (!m->path || !m->name) {
				free (m->path);
				free (m->name);
				return false;
			}
			char *del = strstr (m->name, " (deleted)");
			if (del) {
				*del = '\0';
			}
			m->base = r->start;
			m->end = r->end;
			s->n_modules++;
		}
		if (r->start < m->base) {
			m->base = r->start;
		}
		if (r->end > m->end) {
			m->end = r->end;
		}
		if (r->perms[2] == 'x' && r->perms[0] != 'r') {
			m->exec_only = true;
		}
	}
	if (s->n_modules) {
		qsort (s->modules, s->n_modules, sizeof (RnModule), module_cmp);
	}
	for (i = 0; i < s->n_modules; i++) {
		for (j = i + 1; j < s->n_modules; j++) {
			if (!strcmp (s->modules[i].name, s->modules[j].name)) {
				s->modules[i].dup_name = true;
				s->modules[j].dup_name = true;
			}
		}
	}
	return true;
}

bool rn_ranges_refresh(RenefSession *s, RnBuf *err) {
	MapsCtx ctx;
	long from = 0;
	int pages = 0;
	memset (&ctx, 0, sizeof (ctx));

	do {
		RnBuf reply;
		bool failed = false;
		char *lua = r_str_newf (LUA_MAPS, from, page_lines (s), page_bytes (s));
		if (!lua) {
			free_ranges (ctx.v, ctx.n);
			if (err) {
				rn_buf_puts (err, "out of memory\n");
			}
			return false;
		}
		rn_buf_init (&reply);
		ctx.got_end = false;
		ctx.more = 0;
		RnStatus st = rn_exec (s, lua, 0, &reply);
		free (lua);
		bool dropped = st == RN_OK && reply_dropped (&reply);
		/* A page carries its own end line, so in paged mode the notice
		 * says nothing about this reply: on an unframed connection it
		 * belongs to the unpaged attempt before it and only arrives now. */
		if (st == RN_OK && (!dropped || s->paged)) {
			rn_scan_reply (s, &reply, maps_line, &ctx, NULL, &failed);
		}
		rn_buf_fini (&reply);
		if (st == RN_OK && !s->paged && (dropped || !ctx.got_end) && !ctx.oom) {
			/* Incomplete, or gone altogether (a message larger than
			 * the agent's queue is dropped whole): start over, a page
			 * at a time. */
			free_ranges (ctx.v, ctx.n);
			memset (&ctx, 0, sizeof (ctx));
			s->paged = true;
			if (!dropped) {
				/* nothing came back at all: the notice is still on its way */
				s->own_drop_notices = 1;
			}
			from = 0;
			ctx.more = 1;
			continue;
		}
		if (st != RN_OK || !ctx.got_end || ctx.oom) {
			if (err) {
				rn_buf_appendf (err, "cannot read the memory map: %s\n",
					st != RN_OK? rn_status_str (st): (ctx.oom? "out of memory": "no answer from target"));
			}
			free_ranges (ctx.v, ctx.n);
			return false;
		}
		from = ctx.next;
	} while (ctx.more && ++pages < RN_MAX_PAGES);

	rn_conn_lock (&s->conn);
	free_ranges (s->ranges, s->n_ranges);
	s->ranges = ctx.v;
	s->n_ranges = ctx.n;
	s->modlist_only = ctx.modlist;
	bool ok = build_modules (s);
	rn_conn_unlock (&s->conn);
	if (!ok && err) {
		rn_buf_puts (err, "out of memory\n");
	}
	return ok;
}

bool rn_ranges_ensure(RenefSession *s, RnBuf *err) {
	return s->n_ranges > 0 || rn_ranges_refresh (s, err);
}

const RnRange *rn_range_at(RenefSession *s, ut64 addr) {
	size_t lo = 0, hi = s->n_ranges;
	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;
		const RnRange *r = &s->ranges[mid];
		if (addr < r->start) {
			hi = mid;
		} else if (addr >= r->end) {
			lo = mid + 1;
		} else {
			return r;
		}
	}
	return NULL;
}

const RnModule *rn_module_at(RenefSession *s, ut64 addr) {
	const RnRange *r = rn_range_at (s, addr);
	size_t i;
	if (!r) {
		return NULL;
	}
	for (i = 0; i < s->n_modules; i++) {
		const RnModule *m = &s->modules[i];
		if (addr >= m->base && addr < m->end && !strcmp (m->path, r->path)) {
			return m;
		}
	}
	return NULL;
}

const RnModule *rn_module_find(RenefSession *s, const char *name, bool *ambiguous) {
	const RnModule *hit = NULL;
	size_t i;
	int n = 0;
	if (ambiguous) {
		*ambiguous = false;
	}
	for (i = 0; i < s->n_modules; i++) {
		if (!strcmp (s->modules[i].path, name)) {
			return &s->modules[i];
		}
	}
	for (i = 0; i < s->n_modules; i++) {
		if (!strcmp (s->modules[i].name, name)) {
			hit = hit? hit: &s->modules[i];
			n++;
		}
	}
	if (n == 0) {
		for (i = 0; i < s->n_modules; i++) {
			if (strstr (s->modules[i].path, name)) {
				hit = hit? hit: &s->modules[i];
				n++;
			}
		}
	}
	if (n > 1 && ambiguous) {
		*ambiguous = true;
	}
	return hit;
}

const char *rn_module_luaname(const RnModule *m) {
	return strlen (m->path) <= 127? m->path: m->name;
}

char *rn_addr_label(RenefSession *s, ut64 addr) {
	const RnModule *m = rn_module_at (s, addr);
	if (m) {
		return r_str_newf ("%s+0x%" PFMT64x, m->name, addr - m->base);
	}
	return r_str_newf ("0x%" PFMT64x, addr);
}

/* ---- radare2 side ---- */

static const char *range_name(const RnRange *r) {
	if (!*r->path) {
		return "anon";
	}
	if (r->path[0] == '/') {
		const char *b = strrchr (r->path, '/');
		return b[1]? b + 1: r->path;
	}
	return r->path;
}

/* Replaces the descriptor's maps with one per mapped range of the target.
 * radare2 then knows what is unmapped without asking the device, shows
 * the module behind an address in `om`, and can bound `search.in`. */
static int apply_maps(RenefSession *s) {
	size_t i = 0;
	int count = 0;
	if (s->fd < 0 || !s->io || !s->n_ranges || s->modlist_only) {
		return 0;
	}
	r_io_map_del_for_fd (s->io, s->fd);
	while (i < s->n_ranges) {
		const RnRange *r = &s->ranges[i];
		ut64 end = r->end;
		size_t j = i + 1;
		while (j < s->n_ranges && s->ranges[j].start == end
				&& !strcmp (s->ranges[j].perms, r->perms)
				&& !strcmp (s->ranges[j].path, r->path)) {
			end = s->ranges[j].end;
			j++;
		}
		i = j;
		bool rd = r->perms[0] == 'r', wr = r->perms[1] == 'w', ex = r->perms[2] == 'x';
		if (!rd && !wr && !ex) {
			continue;       /* guard pages and reservations */
		}
		/* always writable for radare2: the agent can patch read-only
		 * pages, so `w` commands should not be refused up front */
		int perm = R_PERM_W | (rd? R_PERM_R: 0) | (ex? R_PERM_X: 0);
		if (ex && !rd && s->conn.framed && s->memdump_cmd >= 0) {
			/* execute-only code: the target cannot read it, but the
			 * server can (see proc_read in renef_memory.c), and radare2
			 * does not even ask for bytes of a map without R */
			perm |= R_PERM_R;
		}
		RIOMap *map = r_io_map_add (s->io, s->fd, perm, r->start, r->start, end - r->start);
		if (map) {
			r_io_map_set_name (map, range_name (r));
			count++;
		}
	}
	s->maps_applied = true;
	return count;
}

static char *module_flag(const RnModule *m) {
	char *fn = rn_flag_name (m->name);
	if (!fn) {
		return NULL;
	}
	char *out = m->dup_name
		? r_str_newf ("lib.%s_%" PFMT64x, fn, m->base)
		: r_str_newf ("lib.%s", fn);
	free (fn);
	return out;
}

static void apply_module_flags(RenefSession *s) {
	size_t i;
	if (!rn_r2_available (s) || !s->n_modules) {
		return;
	}
	rn_r2cmd (s, "fs+renef.modules");
	rn_r2cmd (s, "f-lib.*");
	for (i = 0; i < s->n_modules; i++) {
		const RnModule *m = &s->modules[i];
		char *fl = module_flag (m);
		if (fl) {
			rn_r2cmdf (s, "f %s 0x%" PFMT64x " 0x%" PFMT64x, fl, m->end - m->base, m->base);
			free (fl);
		}
	}
	rn_r2cmd (s, "fs-");
}

void rn_init_hook(RenefSession *s) {
	if (!s->autosync || !rn_r2_available (s) || s->fd < 0 || !rn_conn_is_open (&s->conn)) {
		return;
	}
	bool first = !s->init_done;
	if (first) {
		RnBuf err;
		s->init_done = true;
		/* renef targets are always AArch64 */
		rn_r2cmd (s, "e asm.arch=arm");
		rn_r2cmd (s, "e asm.bits=64");
		rn_buf_init (&err);
		if (!rn_ranges_refresh (s, &err)) {
			R_LOG_WARN ("renef: %s", err.data? err.data: "cannot read the memory map");
			rn_buf_fini (&err);
			return;
		}
		rn_buf_fini (&err);
		apply_module_flags (s);
	}
	/* radare2 adds its own map over the whole descriptor after opening
	 * it and calls this hook again once that is done */
	int maps = 0;
	if (s->maps_mode == RN_MAPS_RANGES) {
		maps = apply_maps (s);
	}
	if (first) {
		bool amb = false;
		const RnModule *libc = rn_module_find (s, "libc.so", &amb);
		if (!libc && s->n_modules) {
			libc = &s->modules[0];
		}
		if (libc) {
			rn_r2cmdf (s, "s 0x%" PFMT64x, libc->base);
		}
		R_LOG_INFO ("renef: %d ranges, %d modules%s", (int)s->n_ranges, (int)s->n_modules,
			s->modlist_only? " (module list only: /proc/self/maps not readable)": "");
		(void)maps;
	}
}

/* ---- listings ---- */

static bool arg_matches(const char *filter, const char *text) {
	return !filter || !*filter || strstr (text, filter);
}

char *rn_cmd_dm(RenefSession *s, const char *args, bool star) {
	RnBuf out;
	size_t i;
	rn_buf_init (&out);
	if (!rn_ranges_refresh (s, &out)) {
		return rn_buf_steal (&out, NULL);
	}
	if (star) {
		rn_buf_puts (&out, "fs+renef.maps\n");
	}
	for (i = 0; i < s->n_ranges; i++) {
		const RnRange *r = &s->ranges[i];
		if (!arg_matches (args, r->path)) {
			continue;
		}
		if (star) {
			char *fn = rn_flag_name (range_name (r));
			char *pf = rn_flag_name (r->perms);
			if (fn && pf) {
				rn_buf_appendf (&out, "f map.%s.%s 0x%" PFMT64x " 0x%" PFMT64x "\n",
					fn, pf, r->end - r->start, r->start);
			}
			free (fn);
			free (pf);
		} else {
			rn_buf_appendf (&out, "0x%016" PFMT64x " - 0x%016" PFMT64x " %s %08" PFMT64x " %s\n",
				r->start, r->end, r->perms, r->offset, r->path);
		}
	}
	if (star) {
		rn_buf_puts (&out, "fs-\n");
	}
	return rn_buf_steal (&out, NULL);
}

char *rn_cmd_modules(RenefSession *s, const char *args, bool star) {
	RnBuf out;
	size_t i;
	rn_buf_init (&out);
	if (!rn_ranges_refresh (s, &out)) {
		return rn_buf_steal (&out, NULL);
	}
	if (star) {
		rn_buf_puts (&out, "fs+renef.modules\n");
	}
	for (i = 0; i < s->n_modules; i++) {
		const RnModule *m = &s->modules[i];
		if (!arg_matches (args, m->path)) {
			continue;
		}
		if (star) {
			char *fl = module_flag (m);
			if (fl) {
				rn_buf_appendf (&out, "f %s 0x%" PFMT64x " 0x%" PFMT64x "\n", fl, m->end - m->base, m->base);
				free (fl);
			}
		} else {
			rn_buf_appendf (&out, "0x%016" PFMT64x " - 0x%016" PFMT64x " %s%s %s\n",
				m->base, m->end, m->exec_only? "xom ": "", m->name, m->path);
		}
	}
	if (star) {
		rn_buf_puts (&out, "fs-\n");
	}
	return rn_buf_steal (&out, NULL);
}

/* ---- exports / symbols ---- */

typedef void (*SymCb)(void *user, ut64 offset, const char *name);

typedef struct {
	SymCb cb;
	void *user;
	long total;
	long next;
	ut64 base;
	bool got_end;
	char err[160];
} SymCtx;

static void sym_line(void *user, const char *line, size_t len) {
	SymCtx *ctx = user;
	if (len < 2) {
		return;
	}
	if (line[0] == 'X') {
		const char *sp = memchr (line, ' ', len);
		if (!sp || sp == line + 1) {
			return;
		}
		char *name = r_str_ndup (sp + 1, (int)(len - (size_t)(sp + 1 - line)));
		char num[20];
		size_t nl = (size_t)(sp - line - 1);
		if (name && nl < sizeof (num)) {
			memcpy (num, line + 1, nl);
			num[nl] = '\0';
			ut64 off = strtoull (num, NULL, 16);
			if (off && *name) {
				ctx->cb (ctx->user, off, name);
			}
		}
		free (name);
	} else if (line[0] == 'N') {
		char tmp[64];
		unsigned long long b = 0;
		size_t n = len - 1 < sizeof (tmp) - 1? len - 1: sizeof (tmp) - 1;
		memcpy (tmp, line + 1, n);
		tmp[n] = '\0';
		if (sscanf (tmp, "%ld %ld %llx", &ctx->total, &ctx->next, &b) == 3) {
			ctx->base = b;
			ctx->got_end = true;
		}
	} else if (line[0] == 'E') {
		size_t n = len - 2 < sizeof (ctx->err) - 1? len - 2: sizeof (ctx->err) - 1;
		memcpy (ctx->err, line + 2, n);
		ctx->err[n] = '\0';
	}
}

/* Calls cb for every export (or .symtab symbol) of `lib`. *base receives
 * the load address the agent uses for it. */
static bool symbols_fetch(RenefSession *s, const char *lib, bool symtab, SymCb cb, void *user,
		ut64 *base, long *total, RnBuf *err) {
	SymCtx ctx;
	RnBuf q;
	long from = 1;
	int pages = 0;
	memset (&ctx, 0, sizeof (ctx));
	ctx.cb = cb;
	ctx.user = user;
	rn_buf_init (&q);
	if (!rn_lua_quote (&q, lib, strlen (lib))) {
		rn_buf_fini (&q);
		return false;
	}
	for (;;) {
		RnBuf reply;
		char *lua = r_str_newf (LUA_SYMS, q.data, from, symtab? 1: 0, symtab? "symbols": "exports",
			page_lines (s), page_bytes (s));
		if (!lua) {
			break;
		}
		rn_buf_init (&reply);
		ctx.got_end = false;
		RnStatus st = rn_exec (s, lua, 0, &reply);
		free (lua);
		if (st == RN_OK && !s->paged && reply_dropped (&reply)) {
			/* some entries are missing: the caller has to start over */
			rn_buf_fini (&reply);
			s->paged = true;
			if (err) {
				rn_buf_appendf (err, "%s: the agent dropped part of the listing; "
					"it will be fetched in pages from now on, run the command again\n", lib);
			}
			rn_buf_fini (&q);
			return false;
		}
		if (st == RN_OK) {
			rn_scan_reply (s, &reply, sym_line, &ctx, NULL, NULL);
		}
		rn_buf_fini (&reply);
		if (st != RN_OK || !ctx.got_end) {
			if (err) {
				rn_buf_appendf (err, "%s: %s\n", lib, st != RN_OK? rn_status_str (st)
					: (*ctx.err? ctx.err: "no answer from target"));
			}
			rn_buf_fini (&q);
			return false;
		}
		if (ctx.next > ctx.total || ctx.next <= from || ++pages >= RN_MAX_PAGES) {
			break;
		}
		from = ctx.next;
	}
	rn_buf_fini (&q);
	if (base) {
		*base = ctx.base;
	}
	if (total) {
		*total = ctx.total;
	}
	return true;
}

typedef struct {
	ut64 off;
	char *name;
} SymEnt;

typedef struct {
	SymEnt *v;
	size_t n;
	size_t cap;
} SymList;

static void sym_collect(void *user, ut64 offset, const char *name) {
	SymList *l = user;
	if (l->n == l->cap) {
		size_t ncap = l->cap? l->cap * 2: 1024;
		SymEnt *nv = realloc (l->v, ncap * sizeof (SymEnt));
		if (!nv) {
			return;
		}
		l->v = nv;
		l->cap = ncap;
	}
	l->v[l->n].off = offset;
	l->v[l->n].name = strdup (name);
	if (l->v[l->n].name) {
		l->n++;
	}
}

static void sym_list_free(SymList *l) {
	size_t i;
	for (i = 0; i < l->n; i++) {
		free (l->v[i].name);
	}
	free (l->v);
}

/* Resolves the module a command refers to: by name, or the one at the
 * current seek when no name is given. *luaname is what to pass to Lua. */
static bool resolve_module(RenefSession *s, const char *arg, const RnModule **mod, const char **luaname, RnBuf *err) {
	*mod = NULL;
	*luaname = NULL;
	if (!rn_ranges_ensure (s, err)) {
		return false;
	}
	if (!arg || !*arg) {
		ut64 here = s->off;
		rn_r2num (s, "$$", &here);
		*mod = rn_module_at (s, here);
		if (!*mod) {
			rn_buf_appendf (err, "0x%" PFMT64x " is not inside a module; give a module name\n", here);
			return false;
		}
	} else {
		bool amb = false;
		*mod = rn_module_find (s, arg, &amb);
		if (amb) {
			rn_buf_appendf (err, "'%s' matches several modules (see :il %s); use the full path\n", arg, arg);
			return false;
		}
	}
	/* a library the map does not know may still be known to the agent */
	*luaname = *mod? rn_module_luaname (*mod): arg;
	return true;
}

/* Fetches the symbols of the module named by `arg` and either formats
 * them into `out` or defines them as flags. */
static bool symbols_run(RenefSession *s, const char *arg, bool symtab, bool star, bool apply, RnBuf *out, long *count) {
	const RnModule *mod;
	const char *luaname;
	SymList list = { NULL, 0, 0 };
	ut64 base = 0;
	size_t i;

	if (!resolve_module (s, arg, &mod, &luaname, out)) {
		return false;
	}
	char *lib = strdup (luaname);
	char *modname = strdup (mod? mod->name: luaname);
	ut64 modbase = mod? mod->base: 0;
	if (!lib || !modname || !symbols_fetch (s, lib, symtab, sym_collect, &list, &base, NULL, out)) {
		free (lib);
		free (modname);
		sym_list_free (&list);
		return false;
	}
	if (!base) {
		base = modbase;
	}
	char *mf = rn_flag_name (modname);
	const char *space = symtab? "renef.symbols": "renef.exports";
	if (apply) {
		rn_r2cmdf (s, "fs+%s", space);
	} else if (star) {
		rn_buf_appendf (out, "fs+%s\n", space);
	}
	for (i = 0; i < list.n; i++) {
		ut64 addr = base + list.v[i].off;
		if (!apply && !star) {
			rn_buf_appendf (out, "0x%016" PFMT64x " %s\n", addr, list.v[i].name);
			continue;
		}
		char *sf = rn_flag_name (list.v[i].name);
		if (sf && mf) {
			if (apply) {
				rn_r2cmdf (s, "f sym.%s.%s 1 0x%" PFMT64x, mf, sf, addr);
			} else {
				rn_buf_appendf (out, "f sym.%s.%s 1 0x%" PFMT64x "\n", mf, sf, addr);
			}
		}
		free (sf);
	}
	if (apply) {
		rn_r2cmd (s, "fs-");
	} else if (star) {
		rn_buf_puts (out, "fs-\n");
	}
	if (count) {
		*count = (long)list.n;
	}
	free (mf);
	free (lib);
	free (modname);
	sym_list_free (&list);
	return true;
}

char *rn_cmd_symbols(RenefSession *s, const char *args, bool star, bool symtab) {
	RnBuf out;
	rn_buf_init (&out);
	symbols_run (s, args, symtab, star, false, &out, NULL);
	return rn_buf_steal (&out, NULL);
}

char *rn_cmd_sync(RenefSession *s, const char *args) {
	RnBuf out;
	bool symtab = false;
	rn_buf_init (&out);
	if (!strncmp (args, "-s", 2) && (args[2] == ' ' || !args[2])) {
		symtab = true;
		args += 2;
		while (*args == ' ') {
			args++;
		}
	}
	if (!rn_ranges_refresh (s, &out)) {
		return rn_buf_steal (&out, NULL);
	}
	int maps = 0;
	if (s->maps_mode == RN_MAPS_RANGES) {
		maps = apply_maps (s);
	}
	apply_module_flags (s);
	rn_cache_flush (s);
	rn_buf_appendf (&out, "%d ranges, %d modules", (int)s->n_ranges, (int)s->n_modules);
	if (s->maps_mode == RN_MAPS_RANGES && !s->modlist_only) {
		rn_buf_appendf (&out, ", %d io maps", maps);
	}
	rn_buf_puts (&out, "\n");
	if (s->modlist_only) {
		rn_buf_puts (&out, "note: /proc/self/maps was not readable in the target, only the first mapping of each library is known\n");
	}
	if (*args) {
		long n = 0;
		if (symbols_run (s, args, false, false, true, &out, &n)) {
			rn_buf_appendf (&out, "%ld exports of %s flagged\n", n, args);
		}
		if (symtab && symbols_run (s, args, true, false, true, &out, &n)) {
			rn_buf_appendf (&out, "%ld symbols of %s flagged\n", n, args);
		}
	}
	return rn_buf_steal (&out, NULL);
}
