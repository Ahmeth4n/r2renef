/* r2renef - MIT - Copyright 2025-2026 */

#include "renef_commands.h"
#include "renef_java.h"
#include "renef_maps.h"
#include "renef_memory.h"
#include "renef_session.h"

#include <r_util.h>

#define RN_SCRIPT_MAX (4 * 1024 * 1024)
#define RN_BT_MAX 64

static const char HELP[] =
	"r2renef commands (anything else after ':' is sent to renef_server as is)\n"
	"  :?                         this help\n"
	"  :info                      connection, target and read path\n"
	"  :raw <cmd>                 send <cmd> to renef_server without interpreting it\n"
	"  :l <file.lua>              run a local Lua script in the target\n"
	"  :watch [seconds]           follow hook/trace output (^C or the time limit stops)\n"
	"maps and symbols\n"
	"  :sync [-s] [module]        refresh io maps and lib.* flags; with a module also\n"
	"                             flag its exports (-s: its .symtab symbols too)\n"
	"  :dm[*] [filter]            memory ranges of the target\n"
	"  :il[*] [filter]            loaded modules (also :dmm)\n"
	"  :ie[*] [module]            exports of a module (default: the one at $$)\n"
	"  :is[*] [module]            .symtab symbols of a module\n"
	"hooks\n"
	"  :hook [addr] [-i|-g[=lib]] [-r] [-b] [-e <lua>]\n"
	"                             hook the function at addr (default $$)\n"
	"       -i        inline (trampoline) hook, also on execute-only code\n"
	"       -g[=lib]  PLT/GOT hook: patch the call sites in <lib> (default *)\n"
	"       -r        also log the return value\n"
	"       -b        log a backtrace on every call\n"
	"       -e <lua>  body of onEnter(args) instead of the default logger\n"
	"  :hooks                     list hooks and sync their flags/comments\n"
	"  :unhook <id>|all           remove hook(s)\n"
	"  :hookgen [addr]            print a hook script template for addr (default $$)\n"
	"  :bt[*] [addr]              last backtrace captured by a :hook -b hook\n"
	"java\n"
	"  :jc [-n max] [filter]      classes of the app (name contains <filter>)\n"
	"  :jm [-s] [-a] <class> [filter]\n"
	"                             methods and constructors of a class\n"
	"  :jhook <class> <method> [(types)] [-r <value>] [-k] [-b] [-n <N>] [-s] [-e <lua>]\n"
	"                             hook a Java method (:jhook alone explains the options);\n"
	"                             :hooks lists Java hooks as [jN], :unhook jN removes one\n"
	"  :jni <class> | -a [filter]  native methods and the functions they run (flags sym.jni.*)\n"
	"  :jcode <class> <method> [(types)]\n"
	"                             seek to the compiled code of a Java method\n"
	"tracing and search\n"
	"  :strace <a,b,..> [-f lib]  trace syscalls (output is asynchronous: :watch)\n"
	"  :strace -a | -c <category> | --list [category] | --active | --stop | -u <a,b>\n"
	"  :/x [-m module] <hex>      search bytes in the target (?? or .. = any byte)\n"
	"  :/ [-m module] <text>      search a string in the target\n"
	"  :cache [flush|<ms>]        page cache lifetime\n"
	"append * to print radare2 commands instead (use as .:il*)\n";

/* ---- small helpers ---- */

static const char *skip_ws(const char *p) {
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	return p;
}

/* copies the next blank-delimited token and advances *p past it */
static char *take_token(const char **p) {
	const char *s = skip_ws (*p);
	const char *e = s;
	while (*e && *e != ' ' && *e != '\t') {
		e++;
	}
	*p = skip_ws (e);
	return r_str_ndup (s, (int)(e - s));
}

static char *finish(RnBuf *out) {
	if (out->len && out->data[out->len - 1] != '\n') {
		rn_buf_append (out, "\n", 1);
	}
	if (!out->len) {
		rn_buf_fini (out);
		return NULL;
	}
	return rn_buf_steal (out, NULL);
}

static bool word_ok(const char *s) {
	if (!*s) {
		return false;
	}
	for (; *s; s++) {
		char c = *s;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
			return false;
		}
	}
	return true;
}

/* evaluates an address expression in radare2, plain numbers without it */
static bool eval_addr(RenefSession *s, const char *expr, ut64 *out) {
	if (!expr || !*expr) {
		expr = "$$";
	}
	if (rn_r2num (s, expr, out)) {
		return true;
	}
	if (!strcmp (expr, "$$")) {
		*out = s->off;
		return true;
	}
	char *end = NULL;
	*out = strtoull (expr, &end, 0);
	return end && end != expr && !*end;
}

/* ---- hook records ---- */

static RnHook *hook_at(RenefSession *s, ut64 addr) {
	size_t i;
	for (i = 0; i < s->n_hooks; i++) {
		if (s->hooks[i].addr == addr) {
			return &s->hooks[i];
		}
	}
	return NULL;
}

static RnHook *hook_by_id(RenefSession *s, int id) {
	size_t i;
	for (i = 0; i < s->n_hooks; i++) {
		if (s->hooks[i].id == id) {
			return &s->hooks[i];
		}
	}
	return NULL;
}

static const char *hook_kind(const RnHook *h) {
	return h->got? "plt/got": (h->foreign? "set by a script": "inline");
}

static char *hook_flag(const RnHook *h) {
	char *fn = rn_flag_name (h->label);
	char *out = fn? r_str_newf ("hook.%s", fn): NULL;
	free (fn);
	return out;
}

static void hook_comment(RenefSession *s, RnHook *h) {
	RnBuf txt, b64;
	rn_buf_init (&txt);
	rn_buf_init (&b64);
	if (h->id >= 0) {
		rn_buf_appendf (&txt, "renef hook #%d %s (%s)", h->id, h->label, hook_kind (h));
	} else {
		rn_buf_appendf (&txt, "renef hook %s (%s)", h->label, hook_kind (h));
	}
	if (h->hits) {
		rn_buf_appendf (&txt, ": %lu hits", h->hits);
		if (h->last) {
			rn_buf_appendf (&txt, ", last %s", h->last);
		}
	}
	if (txt.data && rn_base64_encode (&b64, txt.data, txt.len)) {
		rn_r2cmdf (s, "CCu base64:%s @ 0x%" PFMT64x, b64.data, h->addr);
	}
	h->dirty = false;
	rn_buf_fini (&txt);
	rn_buf_fini (&b64);
}

static void hook_mark(RenefSession *s, RnHook *h) {
	char *fl = hook_flag (h);
	if (fl) {
		rn_r2cmd (s, "fs+renef.hooks");
		rn_r2cmdf (s, "f %s 1 0x%" PFMT64x, fl, h->addr);
		rn_r2cmd (s, "fs-");
		free (fl);
	}
	hook_comment (s, h);
}

static RnHook *hook_add(RenefSession *s, int id, ut64 addr, bool got, const char *label) {
	RnHook *h = hook_at (s, addr);
	if (!h) {
		RnHook *nv = realloc (s->hooks, (s->n_hooks + 1) * sizeof (RnHook));
		if (!nv) {
			return NULL;
		}
		s->hooks = nv;
		h = &s->hooks[s->n_hooks++];
		memset (h, 0, sizeof (*h));
		h->addr = addr;
	}
	free (h->label);
	h->label = strdup (label);
	h->id = id;
	h->got = got;
	h->foreign = false;
	if (!h->label) {
		s->n_hooks--;
		return NULL;
	}
	return h;
}

static void hook_remove(RenefSession *s, RnHook *h) {
	char *fl = hook_flag (h);
	if (fl) {
		rn_r2cmdf (s, "f-%s", fl);
		free (fl);
	}
	rn_r2cmdf (s, "CC- @ 0x%" PFMT64x, h->addr);
	free (h->label);
	free (h->last);
	free (h->bt);
	size_t idx = (size_t)(h - s->hooks);
	memmove (h, h + 1, (s->n_hooks - idx - 1) * sizeof (RnHook));
	s->n_hooks--;
}

/* ---- unsolicited output ----
 * The callbacks installed by :hook print lines that start with
 * "[hook <label> @0x<addr>]", "[ret  ...]" or "[bt   ...]". Whenever such
 * output passes through the plugin it is counted against the hook so the
 * comment at the hooked address can say what happened there. */

static void hook_note_line(RenefSession *s, const char *line, size_t len) {
	int kind;
	if (len > 7 && !memcmp (line, "[hook ", 6)) {
		kind = 0;
	} else if (len > 7 && !memcmp (line, "[ret  ", 6)) {
		kind = 1;
	} else if (len > 7 && !memcmp (line, "[bt   ", 6)) {
		kind = 2;
	} else {
		return;
	}
	const char *close = memchr (line, ']', len);
	if (!close) {
		return;
	}
	const char *at = close;
	while (at > line && *at != '@') {
		at--;
	}
	if (*at != '@' || close - at < 4 || at[1] != '0' || at[2] != 'x') {
		return;
	}
	char num[20];
	size_t nl = (size_t)(close - at - 3);
	if (nl == 0 || nl >= sizeof (num)) {
		return;
	}
	memcpy (num, at + 3, nl);
	num[nl] = '\0';
	RnHook *h = hook_at (s, strtoull (num, NULL, 16));
	if (!h) {
		return;
	}
	const char *rest = close + 1;
	size_t rl = len - (size_t)(rest - line);
	while (rl && *rest == ' ') {
		rest++;
		rl--;
	}
	if (kind == 2) {
		/* "#NN 0x<pc> ..." */
		const char *x = memchr (rest, 'x', rl);
		if (x && h->bt_len < RN_BT_MAX) {
			if (!h->bt) {
				h->bt = calloc (RN_BT_MAX, sizeof (ut64));
			}
			if (h->bt) {
				char pc[20];
				size_t pl = 0;
				x++;
				while (x + pl < rest + rl && isxdigit ((unsigned char)x[pl]) && pl < sizeof (pc) - 1) {
					pc[pl] = x[pl];
					pl++;
				}
				pc[pl] = '\0';
				h->bt[h->bt_len++] = strtoull (pc, NULL, 16);
				h->bt_stamp = rn_now_ms ();
			}
		}
		return;
	}
	if (kind == 0) {
		h->hits++;
		h->bt_len = 0;  /* the backtrace of this call follows */
		free (h->last);
		h->last = r_str_ndup (rest, (int)(rl > 120? 120: rl));
	} else if (h->last && !strstr (h->last, " ret=")) {
		/* "[ret ...] tid=N x0=0x..": remember it with the call */
		const char *x0 = NULL;
		size_t k;
		for (k = 0; k + 3 <= rl; k++) {
			if (!memcmp (rest + k, "x0=", 3)) {
				x0 = rest + k;
				break;
			}
		}
		if (x0) {
			int vl = (int)(rl - (size_t)(x0 + 3 - rest));
			char *joined = r_str_newf ("%s ret=%.*s", h->last, vl > 40? 40: vl, x0 + 3);
			if (joined) {
				free (h->last);
				h->last = joined;
			}
		}
	}
	h->dirty = true;
}

/* Splits unsolicited output into lines (an incomplete last line waits in
 * s->async_tail), notes hook activity and appends the bytes to `show`. */
static void async_feed(RenefSession *s, const char *data, size_t len, RnBuf *show) {
	rn_buf_append (&s->async_tail, data, len);
	for (;;) {
		const char *nl = s->async_tail.len? memchr (s->async_tail.data, '\n', s->async_tail.len): NULL;
		if (!nl) {
			if (s->async_tail.len > 65536) {
				/* no line is that long: pass it on as it is */
				if (show) {
					rn_buf_append (show, s->async_tail.data, s->async_tail.len);
				}
				rn_buf_clear (&s->async_tail);
			}
			break;
		}
		size_t ll = (size_t)(nl - s->async_tail.data);
		hook_note_line (s, s->async_tail.data, ll);
		if (show) {
			rn_buf_append (show, s->async_tail.data, ll + 1);
		}
		rn_buf_consume (&s->async_tail, ll + 1);
	}
}

static void hooks_update_comments(RenefSession *s) {
	size_t i;
	for (i = 0; i < s->n_hooks; i++) {
		if (s->hooks[i].dirty) {
			hook_comment (s, &s->hooks[i]);
		}
	}
}

/* Shows what the target printed since the last command on stderr, so it
 * never ends up inside a command's own output. */
static void async_flush(RenefSession *s) {
	RnBuf raw, show;
	rn_buf_init (&raw);
	rn_buf_init (&show);
	rn_conn_poll_async (&s->conn);
	rn_conn_take_async (&s->conn, &raw);
	if (raw.len) {
		async_feed (s, raw.data, raw.len, &show);
	}
	if (show.len) {
		fflush (stdout);
		fwrite (show.data, 1, show.len, stderr);
		fflush (stderr);
		hooks_update_comments (s);
	}
	rn_buf_fini (&raw);
	rn_buf_fini (&show);
}

/* ---- passthrough ---- */

static bool is_stream_cmd(const char *cmd) {
	if (!strcmp (cmd, "watch")) {
		return true;
	}
	if (!strncmp (cmd, "renef-strace ", 13)) {
		const char *a = skip_ws (cmd + 13);
		return *a && strcmp (a, "--list") && strcmp (a, "--active") && strcmp (a, "--stop")
			&& strcmp (a, "--help") && strcmp (a, "-h");
	}
	return false;
}

static void stream_cb(void *user, const char *data, size_t len) {
	RenefSession *s = user;
	async_feed (s, data, len, NULL);
	fwrite (data, 1, len, stdout);
	fflush (stdout);
}

/* `:watch` on a server that has the `events` command (Renef local builds).
 *
 * The streaming `watch` command has no end marker: it is stopped by sending
 * a byte and then reading "until quiet". With a hook on a hot function the
 * output never goes quiet, so after the first :watch the connection was out
 * of step with the server (found on a device: every later request timed
 * out). `events <ms>` is an ordinary request - it returns what hooks have
 * printed, waiting at most <ms> for some to arrive - so following output is
 * just a loop of framed requests and cannot desynchronise anything.
 *
 * Returns false if the server does not have the command (caller falls back
 * to the streaming path); otherwise true with the text to show in *result
 * (which may be NULL: nothing to add). */
static void apply_agent_hits(RenefSession *s, const char *listing);
static int server_hook_count(RenefSession *s, RnBuf *raw);

static bool run_watch_events(RenefSession *s, int max_ms, char **result) {
	*result = NULL;
	if (!s->conn.framed || s->events_cmd < 0) {
		return false;
	}
	RnBuf reply, first;
	rn_buf_init (&first);
	if (s->events_cmd == 0) {
		/* the probe already takes events: they are shown below, under
		 * the header, like everything else the watch prints */
		RnStatus pst = rn_conn_request (&s->conn, "events 0", 8, RN_END_QUIET, 5000, &first);
		bool unknown = first.len && memmem (first.data, first.len, "Unknown command", 15);
		if (pst != RN_OK || unknown) {
			rn_buf_fini (&first);
			s->events_cmd = -1;
			return false;
		}
		s->events_cmd = 1;
	}

	RnBuf out, raw, show;
	rn_buf_init (&out);
	rn_buf_init (&raw);
	rn_buf_init (&show);
	/* what arrived before the watch started belongs to it */
	rn_conn_take_async (&s->conn, &raw);
	if (raw.len) {
		async_feed (s, raw.data, raw.len, &show);
	}
	if (show.len) {
		fwrite (show.data, 1, show.len, stdout);
	}
	rn_buf_fini (&raw);
	rn_buf_fini (&show);
	if (max_ms > 0) {
		printf ("Watching for %d ms...\n", max_ms);
	} else {
		printf ("Watching... (^C to stop)\n");
	}
	if (first.len) {
		async_feed (s, first.data, first.len, NULL);
		fwrite (first.data, 1, first.len, stdout);
	}
	rn_buf_fini (&first);
	fflush (stdout);

	long long start = rn_now_ms ();
	RnStatus st = RN_OK;
	/* Each request takes the events the server holds: one that is given
	 * up on would lose them. ^C therefore ends the loop between requests
	 * (at most one `wait` later), not a request. */
	rn_interrupt_scope_begin (&s->conn);
	for (;;) {
		if (rn_interrupt_scope_pending ()) {
			st = RN_INTERRUPTED;
			break;
		}
		int wait = 400;
		if (max_ms > 0) {
			long long left = max_ms - (rn_now_ms () - start);
			if (left <= 0) {
				break;
			}
			if (left < wait) {
				wait = (int)left;
			}
		}
		char cmd[32];
		int n = snprintf (cmd, sizeof (cmd), "events %d", wait);
		rn_buf_init (&reply);
		st = rn_conn_request (&s->conn, cmd, (size_t)n, RN_END_QUIET, wait + 10000, &reply);
		if (reply.len) {
			async_feed (s, reply.data, reply.len, NULL);
			fwrite (reply.data, 1, reply.len, stdout);
			fflush (stdout);
		}
		rn_buf_fini (&reply);
		if (st != RN_OK) {
			break;   /* timeout or a lost connection */
		}
	}
	rn_interrupt_scope_end (&s->conn);
	printf ("\n");
	fflush (stdout);
	if (s->n_hooks && (st == RN_OK || st == RN_INTERRUPTED) && rn_conn_is_open (&s->conn)) {
		/* the lines that were shown are not necessarily every call:
		 * take the counters from the agent */
		RnBuf listing;
		rn_buf_init (&listing);
		if (server_hook_count (s, &listing) >= 0 && listing.data) {
			apply_agent_hits (s, listing.data);
		}
		rn_buf_fini (&listing);
	}
	hooks_update_comments (s);
	rn_cache_flush (s);
	if (st != RN_OK && st != RN_INTERRUPTED) {
		rn_buf_appendf (&out, "watch ended: %s\n", rn_status_str (st));
	}
	*result = finish (&out);
	return true;
}

static char *run_stream(RenefSession *s, const char *cmd, int max_ms) {
	if (!strcmp (cmd, "watch")) {
		char *result = NULL;
		if (run_watch_events (s, max_ms, &result)) {
			return result;
		}
	}
	RnBuf out, raw, show;
	rn_buf_init (&out);
	rn_buf_init (&raw);
	rn_buf_init (&show);
	/* what arrived before the stream started belongs to it */
	rn_conn_take_async (&s->conn, &raw);
	if (raw.len) {
		async_feed (s, raw.data, raw.len, &show);
	}
	if (show.len) {
		fwrite (show.data, 1, show.len, stdout);
	}
	rn_buf_fini (&raw);
	rn_buf_fini (&show);
	if (max_ms > 0) {
		printf ("Watching for %d ms...\n", max_ms);
	} else {
		printf ("Watching... (^C to stop)\n");
	}
	fflush (stdout);
	RnStatus st = rn_conn_stream (&s->conn, cmd, max_ms, stream_cb, s);
	printf ("\n");
	fflush (stdout);
	hooks_update_comments (s);
	rn_cache_flush (s);
	if (st != RN_OK) {
		rn_buf_appendf (&out, "watch ended: %s\n", rn_status_str (st));
	}
	return finish (&out);
}

/* exec/rpc take a leading "--timeout <seconds>": wait at least that long */
static int cmd_timeout(RenefSession *s, const char *cmd) {
	const char *t = strstr (cmd, "--timeout ");
	if (t && t - cmd < 24) {
		long secs = strtol (t + 10, NULL, 10);
		if (secs > 0 && secs <= 3600 && (secs + 5) * 1000 > s->conn.timeout_ms) {
			return (int)(secs + 5) * 1000;
		}
	}
	return 0;
}

/* raw: send the command exactly as typed */
static char *passthrough(RenefSession *s, const char *cmd, bool raw) {
	RnBuf out, wire;
	RnLegacyEnd end = RN_END_QUIET;
	const char *send = cmd;

	if (is_stream_cmd (cmd)) {
		return run_stream (s, cmd, 0);
	}
	rn_buf_init (&out);
	rn_buf_init (&wire);
	if (!strncmp (cmd, "exec ", 5)) {
		end = RN_END_EXEC;
		/* skip the flags the server strips itself */
		const char *code = cmd + 5;
		for (;;) {
			if (!strncmp (code, "--json ", 7)) {
				code += 7;
			} else if (!strncmp (code, "--timeout ", 10)) {
				code += 10;
				while (*code && *code != ' ') {
					code++;
				}
				code = skip_ws (code);
			} else {
				break;
			}
		}
		if (!raw && strstr (code, "//")) {
			/* see rn_exec() */
			rn_buf_append (&wire, cmd, (size_t)(code - cmd));
			if (rn_lua_wrap_script (&wire, code, strlen (code), "=exec")) {
				send = wire.data;
			}
		}
	} else if (!strncmp (cmd, "md ", 3)) {
		end = RN_END_MD;
	} else if (!strcmp (cmd, "ping") || !strncmp (cmd, "spawn ", 6) || !strncmp (cmd, "attach ", 7)) {
		end = RN_END_LINE;
	}
	RnStatus st = rn_conn_request (&s->conn, send, strlen (send), end, cmd_timeout (s, cmd), &out);
	rn_buf_fini (&wire);
	/* nearly every server command can change the target's memory */
	rn_cache_flush (s);
	/* Hook output that arrived while the command ran is part of its reply
	 * (the server no longer discards it). It is shown as it is, but the
	 * hook bookkeeping must see it too, or hits that happen during a
	 * command - e.g. an rpc that triggers the hooked function - are never
	 * counted and no backtrace is recorded for them. */
	if (out.len && memmem (out.data, out.len, "[hook ", 6)) {
		async_feed (s, out.data, out.len, NULL);
		hooks_update_comments (s);
	}
	if (st != RN_OK) {
		if (out.len && out.data[out.len - 1] != '\n') {
			rn_buf_append (&out, "\n", 1);
		}
		rn_buf_appendf (&out, "renef: %s\n", rn_status_str (st));
	}
	return finish (&out);
}

/* ---- :l ---- */

static char *cmd_load(RenefSession *s, const char *args) {
	RnBuf out, lua;
	size_t size = 0;
	rn_buf_init (&out);
	if (!*args) {
		rn_buf_puts (&out, "usage: :l <file.lua>\n");
		return finish (&out);
	}
	char *script = r_file_slurp (args, &size);
	if (!script) {
		rn_buf_appendf (&out, "cannot read %s\n", args);
		return finish (&out);
	}
	if (size > RN_SCRIPT_MAX) {
		free (script);
		rn_buf_appendf (&out, "%s is larger than %d bytes\n", args, RN_SCRIPT_MAX);
		return finish (&out);
	}
	/* Sent hex encoded and rebuilt with load(): the script may contain
	 * anything (newlines, comments, "//") and errors name file:line. */
	rn_buf_init (&lua);
	const char *base = strrchr (args, '/');
	char *chunk = r_str_newf ("@%s", base? base + 1: args);
	RnStatus st = RN_ERROR;
	bool ok = chunk != NULL;
	if (ok && size * 2 <= RN_SCRIPT_CHUNK) {
		ok = rn_buf_puts (&lua, "exec ") && rn_lua_wrap_script (&lua, script, size, chunk);
		st = ok? rn_conn_request (&s->conn, lua.data, lua.len, RN_END_EXEC, 0, &out): RN_ERROR;
	} else if (ok) {
		/* Too long for one command of a public agent (64KB): the hex
		 * text is collected in a global, piece by piece, then loaded. */
		RnBuf hex, reply;
		size_t off = 0;
		rn_buf_init (&hex);
		rn_buf_init (&reply);
		ok = rn_hex_encode (&hex, script, size);
		st = ok? rn_conn_request (&s->conn, "exec __r2s={}", 13, RN_END_EXEC, 0, &reply): RN_ERROR;
		while (ok && st == RN_OK && off < hex.len) {
			size_t n = hex.len - off < RN_SCRIPT_CHUNK? hex.len - off: RN_SCRIPT_CHUNK;
			rn_buf_clear (&lua);
			rn_buf_clear (&reply);
			ok = rn_buf_puts (&lua, "exec __r2s[#__r2s+1]=\"") && rn_buf_append (&lua, hex.data + off, n)
				&& rn_buf_puts (&lua, "\"");
			st = ok? rn_conn_request (&s->conn, lua.data, lua.len, RN_END_EXEC, 0, &reply): RN_ERROR;
			if (st == RN_OK && (!reply.data || strncmp (reply.data, "OK", 2))) {
				rn_buf_appendf (&out, "sending the script failed: %s", reply.data? reply.data: "no answer\n");
				ok = false;
			}
			off += n;
		}
		rn_buf_clear (&lua);
		ok = ok && st == RN_OK
			&& rn_buf_puts (&lua, "exec local h=table.concat(__r2s) __r2s=nil "
				"local f,e=load((h:gsub('%x%x',function(x) return string.char(tonumber(x,16)) end)),")
			&& rn_lua_quote (&lua, chunk, strlen (chunk))
			&& rn_buf_puts (&lua, ") if not f then print('ERROR: '..tostring(e)) else"
				" local ok,e2=pcall(f) if not ok then print('ERROR: '..tostring(e2)) end end");
		if (ok) {
			st = rn_conn_request (&s->conn, lua.data, lua.len, RN_END_EXEC, 0, &out);
		}
		rn_buf_fini (&hex);
		rn_buf_fini (&reply);
	}
	free (chunk);
	free (script);
	rn_buf_fini (&lua);
	rn_cache_flush (s);
	if (!ok && !out.len) {
		rn_buf_puts (&out, "out of memory\n");
	} else if (ok && st != RN_OK) {
		rn_buf_appendf (&out, "renef: %s\n", rn_status_str (st));
	}
	return finish (&out);
}

/* ---- :hook ---- */

typedef struct {
	bool ok;
	ut64 off;
	char name[128];
	char err[256];
} HookCtx;

static void hook_line(void *user, const char *line, size_t len) {
	HookCtx *ctx = user;
	if (len >= 2 && line[0] == 'K') {
		char tmp[160];
		size_t n = len - 1 < sizeof (tmp) - 1? len - 1: sizeof (tmp) - 1;
		memcpy (tmp, line + 1, n);
		tmp[n] = '\0';
		char *sp = strchr (tmp, ' ');
		if (sp) {
			*sp = '\0';
			snprintf (ctx->name, sizeof (ctx->name), "%s", sp + 1);
		}
		ctx->off = strtoull (tmp, NULL, 16);
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

/* Takes the call counters of the agent's hook listing
 * ("  [N] target=0x... hits=M") for the hooks known here. Agents that
 * count calls themselves are exact; without the field the estimate from
 * the hook lines that were seen stays. */
static void apply_agent_hits(RenefSession *s, const char *listing) {
	const char *p = listing;
	while (p && *p) {
		const char *nl = strchr (p, '\n');
		const char *lb = strchr (p, '[');
		if (lb && (!nl || lb < nl)) {
			const char *t = strstr (lb, "target=");
			const char *hs = strstr (lb, " hits=");
			if (t && hs && (!nl || (t < nl && hs < nl))) {
				RnHook *h = hook_at (s, strtoull (t + 7, NULL, 16));
				if (!h) {
					h = hook_by_id (s, atoi (lb + 1));
				}
				unsigned long hits = strtoul (hs + 6, NULL, 10);
				if (h && h->hits != hits) {
					h->hits = hits;
					h->dirty = true;
				}
			}
		}
		p = nl? nl + 1: NULL;
	}
}

/* number of entries in the agent's hook table, -1 if unknown */
static int server_hook_count(RenefSession *s, RnBuf *raw) {
	RnBuf reply;
	int n = -1;
	rn_buf_init (&reply);
	if (rn_conn_request (&s->conn, "hooks", 5, RN_END_QUIET, 0, &reply) == RN_OK && reply.data) {
		const char *p = strstr (reply.data, "Active hooks:");
		if (p) {
			n = atoi (p + 13);
		}
		if (raw) {
			rn_buf_append (raw, reply.data, reply.len);
		}
	}
	rn_buf_fini (&reply);
	return n;
}

static char *cmd_hook(RenefSession *s, const char *args) {
	RnBuf out, lua, q;
	char *expr = NULL, *caller = NULL, *body = NULL, *label = NULL, *tag = NULL;
	bool want_inline = false, want_got = false, on_leave = false, bt = false;
	const char *p = skip_ws (args);
	ut64 addr = 0;

	rn_buf_init (&out);
	rn_buf_init (&lua);
	rn_buf_init (&q);
	while (*p) {
		if (!strncmp (p, "-e ", 3)) {
			body = strdup (skip_ws (p + 3));
			break;
		}
		char *tok = take_token (&p);
		if (!tok) {
			break;
		}
		if (!strcmp (tok, "-i") || !strcmp (tok, "--inline")) {
			want_inline = true;
		} else if (!strncmp (tok, "-g", 2) || !strncmp (tok, "--got", 5)) {
			const char *eq = strchr (tok, '=');
			want_got = true;
			free (caller);
			caller = strdup (eq && eq[1]? eq + 1: "*");
		} else if (!strcmp (tok, "-r")) {
			on_leave = true;
		} else if (!strcmp (tok, "-b")) {
			bt = true;
		} else if (tok[0] == '-' && tok[1] && !isdigit ((unsigned char)tok[1])) {
			rn_buf_appendf (&out, "unknown option %s (see :?)\n", tok);
			free (tok);
			goto done;
		} else if (!expr) {
			expr = tok;
			tok = NULL;
		} else {
			rn_buf_appendf (&out, "unexpected argument %s (see :?)\n", tok);
			free (tok);
			goto done;
		}
		free (tok);
	}
	if (want_inline && want_got) {
		rn_buf_puts (&out, "-i and -g exclude each other\n");
		goto done;
	}
	if (!eval_addr (s, expr, &addr)) {
		rn_buf_appendf (&out, "cannot evaluate address '%s'\n", expr? expr: "$$");
		goto done;
	}
	/* The map may have changed since the last sync. On a legacy server
	 * every extra exec costs seconds, so there the known map is used. */
	if (s->conn.framed? !rn_ranges_refresh (s, &out): !rn_ranges_ensure (s, &out)) {
		goto done;
	}
	const RnRange *range = rn_range_at (s, addr);
	const RnModule *mod = rn_module_at (s, addr);
	if (!range) {
		rn_buf_appendf (&out, "0x%" PFMT64x " is not mapped in the target\n", addr);
		goto done;
	}
	if (!mod) {
		rn_buf_appendf (&out, "0x%" PFMT64x " is not inside a loaded library (%s); renef hooks are addressed as library+offset\n",
			addr, *range->path? range->path: "anonymous memory");
		goto done;
	}
	if (range->perms[2] != 'x') {
		rn_buf_appendf (&out, "0x%" PFMT64x " (%s, %s) is not executable: nothing to hook there\n",
			addr, mod->name, range->perms);
		goto done;
	}
	if (addr & 3) {
		rn_buf_appendf (&out, "0x%" PFMT64x " is not aligned to an AArch64 instruction\n", addr);
		goto done;
	}
	label = r_str_newf ("%s+0x%" PFMT64x, mod->name, addr - mod->base);
	tag = label? r_str_newf ("%s @0x%" PFMT64x, label, addr): NULL;
	if (!tag) {
		goto done;
	}
	if (!want_inline && !want_got && range->perms[0] != 'r') {
		/* An inline hook rewrites the first instructions of the function.
		 * On execute-only text that is the case renef's hook engine was
		 * crashing on before its execute-only fixes (Renef before 0.4.0), so
		 * it is not done without being asked for. A PLT/GOT hook is not
		 * a drop-in replacement either - see the note printed for -g. */
		rn_buf_appendf (&out,
			"%s is in execute-only memory (%s).\n"
			"An inline hook patches that code, which crashes the target on renef builds\n"
			"without the execute-only fixes (before 0.4.0). Choose explicitly:\n"
			"  :hook 0x%" PFMT64x " -g=<lib>   PLT/GOT hook: only calls made from <lib> through its PLT;\n"
			"                         the address must be an exported symbol (-g alone: every library)\n"
			"  :hook 0x%" PFMT64x " -i         inline hook anyway\n",
			label, range->perms, addr, addr);
		goto done;
	}
	bool got = want_got;
	const char *lib = rn_module_luaname (mod);

	bool ok = rn_buf_puts (&lua, "local lib,addr=") && rn_lua_quote (&lua, lib, strlen (lib))
		&& rn_buf_appendf (&lua, ",0x%" PFMT64x " local b=Module.find(lib) "
			"if not b then print('" RN_TAG "E the agent does not know '..lib) return end "
			"if b~=0x%" PFMT64x " then print('" RN_TAG "E '..lib..' resolves to '..string.format('0x%%x',b)"
			"..' in the agent, not to the module mapped at this address') return end "
			"local off=addr-b local nm='' ", addr, mod->base);
	if (ok && got) {
		ok = rn_buf_puts (&lua, "local ex=Module.exports(lib) nm=nil "
			"if ex then for i=1,#ex do if ex[i].offset==off then nm=ex[i].name break end end end "
			"if not nm then print('" RN_TAG "E no exported symbol starts at this address; "
			"a PLT/GOT hook is resolved by symbol name') return end ");
	}
	ok = ok && rn_buf_puts (&lua, "local tag=") && rn_lua_quote (&lua, tag, strlen (tag))
		&& rn_buf_puts (&lua, " local ok,err=pcall(hook,lib,off,{onEnter=function(args) ");
	if (ok && body) {
		ok = rn_buf_puts (&lua, body);
	} else if (ok) {
		ok = rn_buf_puts (&lua, "print(string.format('[hook %s] tid=%d x0=0x%x x1=0x%x x2=0x%x x3=0x%x',"
			"tag,Thread.id(),args[0],args[1],args[2],args[3]))");
	}
	if (ok && bt) {
		ok = rn_buf_puts (&lua, " local t=Thread.backtrace() for i=1,#t do "
			"print(string.format('[bt   %s] #%02d 0x%x %s %s',tag,i-1,t[i].pc,t[i].module or '?',t[i].symbol or '')) end");
	}
	ok = ok && rn_buf_puts (&lua, " end");
	if (ok && on_leave) {
		ok = rn_buf_puts (&lua, ",onLeave=function(retval) "
			"print(string.format('[ret  %s] tid=%d x0=0x%x',tag,Thread.id(),retval)) return retval end");
	}
	if (ok && got) {
		ok = rn_buf_puts (&lua, ",caller=") && rn_lua_quote (&lua, caller, strlen (caller));
	}
	ok = ok && rn_buf_puts (&lua, "}) if ok then print('" RN_TAG "K'..string.format('%x',off)..' '..nm) "
		"else print('" RN_TAG "E '..tostring(err)) end");
	if (!ok) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}

	HookCtx ctx;
	RnBuf reply, other;
	bool failed = false;
	memset (&ctx, 0, sizeof (ctx));
	rn_buf_init (&reply);
	rn_buf_init (&other);
	RnStatus st = rn_exec (s, lua.data, 0, &reply);
	if (st == RN_OK) {
		rn_scan_reply (s, &reply, hook_line, &ctx, &other, &failed);
	}
	rn_buf_fini (&reply);
	if (st != RN_OK || !ctx.ok) {
		rn_buf_appendf (&out, "hook at %s failed: %s\n", label,
			st != RN_OK? rn_status_str (st): (*ctx.err? ctx.err: "the script did not complete"));
		if (other.len) {
			rn_buf_append (&out, other.data, other.len);
		}
		rn_buf_fini (&other);
		goto done;
	}
	rn_buf_fini (&other);
	rn_cache_flush (s);   /* an inline hook changed the code at addr */

	int count = server_hook_count (s, NULL);
	RnHook *h = hook_add (s, count > 0? count - 1: -1, addr, got, label);
	if (h) {
		hook_mark (s, h);
	}
	char idtxt[24] = "";
	if (h && h->id >= 0) {
		snprintf (idtxt, sizeof (idtxt), " #%d", h->id);
	}
	rn_buf_appendf (&out, "hook%s installed at 0x%" PFMT64x " (%s, %s)\n",
		idtxt, addr, label, got? "plt/got": "inline");
	if (got) {
		rn_buf_appendf (&out,
			"note: this is a PLT/GOT hook on the symbol '%s'. It sees calls made through the PLT of\n"
			"%s%s loaded right now (the agent patches at most 64 GOT slots per hook). Calls from\n"
			"inside %s itself, calls through function pointers and libraries loaded later are not seen.\n",
			ctx.name, strcmp (caller, "*")? "": "the libraries", strcmp (caller, "*")? caller: "", mod->name);
	}
	rn_buf_puts (&out, "output is asynchronous: :watch follows it\n");
done:
	free (expr);
	free (caller);
	free (body);
	free (label);
	free (tag);
	rn_buf_fini (&lua);
	rn_buf_fini (&q);
	return finish (&out);
}

/* ---- :hooks / :unhook ---- */

static char *cmd_hooks(RenefSession *s) {
	RnBuf out, raw, err;
	size_t i;
	rn_buf_init (&out);
	rn_buf_init (&raw);
	rn_buf_init (&err);
	int count = server_hook_count (s, &raw);
	if (count < 0) {
		rn_buf_puts (&out, raw.len? raw.data: "no answer from renef_server\n");
		rn_buf_fini (&raw);
		rn_buf_fini (&err);
		return finish (&out);
	}
	rn_buf_append (&out, raw.data, raw.len);
	/* "  [N] target=0x..." is the hooked address. Agents before the fix
	 * of that listing print the first patched GOT slot for a PLT/GOT
	 * hook, which is data: only addresses in executable memory are taken
	 * as hooks. */
	rn_ranges_ensure (s, &err);
	const char *p = raw.data;
	while (p && *p) {
		const char *nl = strchr (p, '\n');
		const char *lb = strchr (p, '[');
		/* "[jN] ..." is a Java hook: those are not tracked here */
		if (lb && (!nl || lb < nl) && lb[1] >= '0' && lb[1] <= '9') {
			int id = atoi (lb + 1);
			const char *t = strstr (lb, "target=");
			RnHook *known = hook_by_id (s, id);
			if (t && (!nl || t < nl)) {
				ut64 addr = strtoull (t + 7, NULL, 16);
				const RnRange *r = rn_range_at (s, addr);
				RnHook *same = hook_at (s, addr);
				if (same) {
					same->id = id;
				} else if (!known && r && r->perms[2] == 'x') {
					char *label = rn_addr_label (s, addr);
					RnHook *h = label? hook_add (s, id, addr, false, label): NULL;
					if (h) {
						/* the list does not say which kind of hook */
						h->foreign = true;
						hook_mark (s, h);
					}
					free (label);
				}
			} else if (known && strstr (lb, "(removed)") && (!nl || strstr (lb, "(removed)") < nl)) {
				hook_remove (s, known);
			}
		}
		p = nl? nl + 1: NULL;
	}
	apply_agent_hits (s, raw.data);
	if (s->n_hooks) {
		rn_buf_puts (&out, "known to r2renef:\n");
	}
	for (i = 0; i < s->n_hooks; i++) {
		const RnHook *h = &s->hooks[i];
		rn_buf_appendf (&out, "  [%d] 0x%" PFMT64x " %s %s hits=%lu%s%s\n", h->id, h->addr, h->label,
			hook_kind (h), h->hits, h->last? " last: ": "", h->last? h->last: "");
	}
	hooks_update_comments (s);
	rn_buf_fini (&raw);
	rn_buf_fini (&err);
	return finish (&out);
}

static char *cmd_unhook(RenefSession *s, const char *args) {
	RnBuf out;
	rn_buf_init (&out);
	if (!*args) {
		rn_buf_puts (&out, "usage: :unhook <id>|all\n");
		return finish (&out);
	}
	char *cmd = r_str_newf ("unhook %s", args);
	if (!cmd) {
		return NULL;
	}
	RnStatus st = rn_conn_request (&s->conn, cmd, strlen (cmd), RN_END_QUIET, 0, &out);
	free (cmd);
	rn_cache_flush (s);
	if (st != RN_OK) {
		rn_buf_appendf (&out, "renef: %s\n", rn_status_str (st));
		return finish (&out);
	}
	if (out.data && !strncmp (out.data, "Removed", 7)) {
		while (s->n_hooks) {
			hook_remove (s, &s->hooks[s->n_hooks - 1]);
		}
	} else if (out.data && !strncmp (out.data, "Hook ", 5) && out.data[5] >= '0' && out.data[5] <= '9') {
		/* "Hook j3 removed" is a Java hook: those have no flag here */
		RnHook *h = hook_by_id (s, atoi (out.data + 5));
		if (h) {
			hook_remove (s, h);
		}
	}
	return finish (&out);
}

/* ---- :bt ---- */

typedef struct {
	ut64 pc[RN_BT_MAX];
	int n;
} BtCtx;

static void bt_line(void *user, const char *line, size_t len) {
	BtCtx *ctx = user;
	if (len > 1 && line[0] == 'T' && ctx->n < RN_BT_MAX) {
		char tmp[20];
		size_t n = len - 1 < sizeof (tmp) - 1? len - 1: sizeof (tmp) - 1;
		memcpy (tmp, line + 1, n);
		tmp[n] = '\0';
		ctx->pc[ctx->n++] = strtoull (tmp, NULL, 16);
	}
}

static char *cmd_bt(RenefSession *s, const char *args, bool star) {
	RnBuf out, err;
	const RnHook *h = NULL;
	BtCtx live;
	const ut64 *pcs = NULL;
	int n = 0, i;
	size_t k;

	rn_buf_init (&out);
	rn_buf_init (&err);
	memset (&live, 0, sizeof (live));
	if (*args) {
		ut64 addr = 0;
		if (!eval_addr (s, args, &addr) || !(h = hook_at (s, addr))) {
			rn_buf_appendf (&out, "no :hook at '%s'\n", args);
			goto done;
		}
		if (!h->bt_len) {
			rn_buf_appendf (&out, "no backtrace captured for %s yet (install it with :hook -b, let it fire, then :watch)\n", h->label);
			goto done;
		}
	} else {
		for (k = 0; k < s->n_hooks; k++) {
			if (s->hooks[k].bt_len && (!h || s->hooks[k].bt_stamp > h->bt_stamp)) {
				h = &s->hooks[k];
			}
		}
	}
	if (h) {
		pcs = h->bt;
		n = h->bt_len;
		if (!star) {
			rn_buf_appendf (&out, "backtrace of the last call that hit %s:\n", h->label);
		}
	} else {
		/* Nothing captured: the only stack that can be walked on demand
		 * is the one of the agent thread running this very request. */
		RnBuf reply;
		rn_buf_init (&reply);
		RnStatus st = rn_exec (s, "local t=Thread.backtrace() for i=1,#t do "
			"print('" RN_TAG "T'..string.format('%x',t[i].pc)) end", 0, &reply);
		if (st == RN_OK) {
			rn_scan_reply (s, &reply, bt_line, &live, NULL, NULL);
		}
		rn_buf_fini (&reply);
		if (st != RN_OK) {
			rn_buf_appendf (&out, "renef: %s\n", rn_status_str (st));
			goto done;
		}
		pcs = live.pc;
		n = live.n;
		if (!star) {
			rn_buf_puts (&out, "no backtrace captured by a hook yet; this is the agent's own command thread\n"
				"(use :hook <addr> -b, let it fire, then :bt)\n");
		}
	}
	rn_ranges_ensure (s, &err);
	if (star) {
		rn_buf_puts (&out, "fs+renef.bt\nf-bt.*\n");
	}
	for (i = 0; i < n; i++) {
		if (star) {
			rn_buf_appendf (&out, "f bt.%02d 1 0x%" PFMT64x "\n", i, pcs[i]);
		} else {
			char *label = rn_addr_label (s, pcs[i]);
			rn_buf_appendf (&out, "#%02d 0x%016" PFMT64x " %s\n", i, pcs[i], label? label: "");
			free (label);
		}
	}
	if (star) {
		rn_buf_puts (&out, "fs-\n");
	}
done:
	rn_buf_fini (&err);
	return finish (&out);
}

/* ---- :strace ---- */

/* appends "'a','b'" for a comma separated list of syscall names */
static bool lua_name_list(RnBuf *lua, const char *list) {
	char *copy = strdup (list);
	char *save = NULL, *tok;
	int n = 0;
	bool ok = copy != NULL;
	for (tok = copy? strtok_r (copy, ",", &save): NULL; ok && tok; tok = strtok_r (NULL, ",", &save)) {
		if (!word_ok (tok)) {
			ok = false;
			break;
		}
		ok = rn_buf_appendf (lua, "%s'%s'", n++? ",": "", tok);
	}
	free (copy);
	return ok && n > 0;
}

static char *cmd_strace(RenefSession *s, const char *args) {
	static const char usage[] =
		"usage: :strace <a,b,..> [-f lib]   trace the named syscalls (optionally only calls from lib)\n"
		"       :strace -a                  trace all known syscalls\n"
		"       :strace -c <category>       file, network, memory, process, ipc\n"
		"       :strace -u <a,b,..>         stop tracing the named syscalls\n"
		"       :strace --list [category] | --active | --stop\n"
		"trace output is asynchronous: follow it with :watch\n";
	RnBuf out, lua, reply;
	bool starts = false;
	const char *p = skip_ws (args);

	rn_buf_init (&out);
	rn_buf_init (&lua);
	rn_buf_init (&reply);
	char *first = take_token (&p);
	bool ok = first != NULL;
	if (!ok || !*first || !strcmp (first, "-h") || !strcmp (first, "--help")) {
		rn_buf_puts (&out, usage);
		goto done;
	}
	if (!strcmp (first, "--stop")) {
		ok = rn_buf_puts (&lua, "Syscall.stop()");
	} else if (!strcmp (first, "--active")) {
		ok = rn_buf_puts (&lua, "local t=Syscall.active() for i=1,#t do "
			"print('  '..t[i].name..' ['..t[i].category..'] '..t[i].hooks..' call sites') end");
	} else if (!strcmp (first, "--list")) {
		if (*p && !word_ok (p)) {
			ok = false;
		} else if (*p) {
			ok = rn_buf_appendf (&lua, "Syscall.list('%s')", p);
		} else {
			ok = rn_buf_puts (&lua, "Syscall.list()");
		}
	} else if (!strcmp (first, "-a")) {
		starts = true;
		ok = rn_buf_puts (&lua, "Syscall.traceAll()");
	} else if (!strcmp (first, "-c")) {
		starts = true;
		ok = word_ok (p) && rn_buf_appendf (&lua, "Syscall.trace({category='%s'})", p);
	} else if (!strcmp (first, "-u")) {
		ok = rn_buf_puts (&lua, "Syscall.untrace(") && lua_name_list (&lua, p) && rn_buf_puts (&lua, ")");
	} else if (first[0] == '-') {
		ok = false;
	} else {
		starts = true;
		ok = rn_buf_puts (&lua, "Syscall.trace(") && lua_name_list (&lua, first);
		if (ok && !strncmp (p, "-f ", 3)) {
			const char *lib = skip_ws (p + 3);
			ok = *lib && rn_buf_puts (&lua, ",{caller=") && rn_lua_quote (&lua, lib, strlen (lib))
				&& rn_buf_puts (&lua, "}");
		} else if (ok && *p) {
			ok = false;
		}
		ok = ok && rn_buf_puts (&lua, ")");
	}
	if (!ok) {
		rn_buf_puts (&out, usage);
		goto done;
	}
	bool failed = false;
	RnStatus st = rn_exec (s, lua.data, 0, &reply);
	if (st != RN_OK) {
		rn_buf_appendf (&out, "renef: %s\n", rn_status_str (st));
		goto done;
	}
	/* Syscall.* reports through print(): everything in the reply that is
	 * not exec's status line is its answer */
	rn_scan_reply (s, &reply, NULL, NULL, &out, &failed);
	if (failed) {
		rn_buf_puts (&out, "the target rejected the request (unknown syscall or category?)\n");
	} else if (starts && out.data && strstr (out.data, "Tracing")) {
		rn_buf_puts (&out, "trace output is asynchronous: follow it with :watch\n");
	}
	rn_cache_flush (s);
done:
	free (first);
	rn_buf_fini (&lua);
	rn_buf_fini (&reply);
	return finish (&out);
}

/* ---- :/ and :/x ---- */

typedef struct {
	ut64 *v;
	int n;
	int cap;
	long total;
} HitCtx;

static void hit_line(void *user, const char *line, size_t len) {
	HitCtx *ctx = user;
	char tmp[24];
	size_t n = len - 1 < sizeof (tmp) - 1? len - 1: sizeof (tmp) - 1;
	if (len < 2) {
		return;
	}
	memcpy (tmp, line + 1, n);
	tmp[n] = '\0';
	if (line[0] == 'N') {
		ctx->total = strtol (tmp, NULL, 10);
	} else if (line[0] == 'S') {
		if (ctx->n == ctx->cap) {
			int ncap = ctx->cap? ctx->cap * 2: 256;
			ut64 *nv = realloc (ctx->v, (size_t)ncap * sizeof (ut64));
			if (!nv) {
				return;
			}
			ctx->v = nv;
			ctx->cap = ncap;
		}
		ctx->v[ctx->n++] = strtoull (tmp, NULL, 16);
	}
}

static char *cmd_search(RenefSession *s, const char *args, bool is_hex, bool star) {
	RnBuf out, lua, reply, err;
	HitCtx ctx;
	char *module = NULL, *pattern = NULL;
	const char *p = skip_ws (args);
	int i;

	rn_buf_init (&out);
	rn_buf_init (&lua);
	rn_buf_init (&reply);
	rn_buf_init (&err);
	memset (&ctx, 0, sizeof (ctx));
	ctx.total = -1;
	if (!strncmp (p, "-m ", 3)) {
		p += 3;
		module = take_token (&p);
	}
	pattern = rn_search_pattern (p, strlen (p), is_hex);
	if (!pattern) {
		rn_buf_appendf (&out, "usage: :/%s [-m module] %s   (1 to 256 bytes)\n", is_hex? "x": "",
			is_hex? "<hex bytes, ?? or .. for any byte>": "<text>");
		goto done;
	}
	/* Memory.search() takes a spaced pattern for bytes and anything else
	 * as a literal string, so text is searched as bytes too: a string
	 * with a blank or "??" in it would otherwise be misread. */
	bool ok = rn_buf_puts (&lua, "local r=Memory.search(") && rn_lua_quote (&lua, pattern, strlen (pattern));
	if (ok && module) {
		bool amb = false;
		rn_ranges_ensure (s, &err);
		const RnModule *m = rn_module_find (s, module, &amb);
		if (amb) {
			rn_buf_appendf (&out, "'%s' matches several modules (see :il %s); use the full path\n", module, module);
			goto done;
		}
		const char *lib = m? m->path: module;
		ok = rn_buf_puts (&lua, ",") && rn_lua_quote (&lua, lib, strlen (lib));
	}
	ok = ok && rn_buf_puts (&lua, ") local o={} for i=1,#r do o[#o+1]='" RN_TAG "S'..string.format('%x',r[i].addr) end "
		"o[#o+1]='" RN_TAG "N'..#r print(table.concat(o,'\\n'))");
	if (!ok) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}
	/* a scan of the whole process can take a while */
	int tmo = s->conn.timeout_ms < 120000? 120000: s->conn.timeout_ms;
	RnStatus st = rn_exec (s, lua.data, tmo, &reply);
	if (st == RN_OK) {
		rn_scan_reply (s, &reply, hit_line, &ctx, NULL, NULL);
	}
	if (st != RN_OK || ctx.total < 0) {
		rn_buf_appendf (&out, "search failed: %s\n", st != RN_OK? rn_status_str (st): "no answer from target");
		goto done;
	}
	rn_ranges_ensure (s, &err);
	if (star) {
		rn_buf_puts (&out, "fs+renef.search\nf-renef.hit*\n");
	} else {
		rn_r2cmd (s, "fs+renef.search");
		rn_r2cmd (s, "f-renef.hit*");
	}
	int plen = (int)(strlen (pattern) / 3);
	for (i = 0; i < ctx.n; i++) {
		if (star) {
			rn_buf_appendf (&out, "f renef.hit%d %d 0x%" PFMT64x "\n", i, plen, ctx.v[i]);
			continue;
		}
		char *label = rn_addr_label (s, ctx.v[i]);
		rn_r2cmdf (s, "f renef.hit%d %d 0x%" PFMT64x, i, plen, ctx.v[i]);
		rn_buf_appendf (&out, "0x%016" PFMT64x " renef.hit%d %s\n", ctx.v[i], i, label? label: "");
		free (label);
	}
	if (star) {
		rn_buf_puts (&out, "fs-\n");
	} else {
		rn_r2cmd (s, "fs-");
		rn_buf_appendf (&out, "%d hits%s\n", ctx.n,
			ctx.n >= 1000? " (the agent stops at 1000 results and 512MB scanned)": "");
	}
done:
	free (module);
	free (pattern);
	free (ctx.v);
	rn_buf_fini (&lua);
	rn_buf_fini (&reply);
	rn_buf_fini (&err);
	return finish (&out);
}

/* ---- :hookgen ---- */

static char *cmd_hookgen(RenefSession *s, const char *args) {
	RnBuf out;
	const char *p = skip_ws (args);
	ut64 addr = 0;

	/* "hookgen <lib> <offset|symbol>" and "hookgen <symbol>" are the
	 * server's own forms; only an address is translated here */
	if (strchr (p, ' ')) {
		char *cmd = r_str_newf ("hookgen %s", p);
		char *res = cmd? passthrough (s, cmd, false): NULL;
		free (cmd);
		return res;
	}
	rn_buf_init (&out);
	if (!eval_addr (s, p, &addr) || !rn_ranges_ensure (s, &out)) {
		if (!out.len) {
			rn_buf_appendf (&out, "cannot evaluate address '%s'\n", p);
		}
		return finish (&out);
	}
	const RnModule *mod = rn_module_at (s, addr);
	if (!mod && *p) {
		/* not an address inside a module: let the server look the
		 * word up as a symbol name */
		char *cmd = r_str_newf ("hookgen %s", p);
		char *res = cmd? passthrough (s, cmd, false): NULL;
		free (cmd);
		rn_buf_fini (&out);
		return res;
	}
	if (!mod) {
		rn_buf_appendf (&out, "0x%" PFMT64x " is not inside a loaded library (try :sync)\n", addr);
		return finish (&out);
	}
	/* the server parses "<lib> <hex offset>" with sscanf("%s %lx") */
	const char *lib = mod->dup_name || strchr (mod->name, ' ')? mod->path: mod->name;
	if (strchr (lib, ' ')) {
		rn_buf_appendf (&out, "the path of %s contains a blank, which hookgen cannot take\n", mod->name);
		return finish (&out);
	}
	char *cmd = r_str_newf ("hookgen %s 0x%" PFMT64x, lib, addr - mod->base);
	if (cmd) {
		RnStatus st = rn_conn_request (&s->conn, cmd, strlen (cmd), RN_END_QUIET, 0, &out);
		if (st != RN_OK) {
			rn_buf_appendf (&out, "renef: %s\n", rn_status_str (st));
		}
		free (cmd);
	}
	return finish (&out);
}

/* ---- :info / :cache / :watch ---- */

static char *cmd_info(RenefSession *s) {
	RnBuf out;
	rn_buf_init (&out);
	rn_buf_appendf (&out, "server    %s:%s (%s)\n", s->conn.host, s->conn.port,
		rn_conn_is_open (&s->conn)? "connected": "closed");
	rn_buf_appendf (&out, "protocol  %s\n", s->conn.framed
		? "framed (@req/@done)": "legacy (reply ends when the line goes quiet)");
	rn_buf_appendf (&out, "target    %s %s, pid %d\n", s->spawn? "spawn": "attach", s->target? s->target: "?", s->pid);
	const char *rp = rn_read_path_name (s);
	rn_buf_appendf (&out, "read path %s%s (lua reads %lu, md reads %lu)\n", rp,
		(!strcmp (rp, "lua") && !s->lua_read_checked)? " (not yet checked against md)": "",
		s->n_lua_reads, s->n_md_reads);
	rn_buf_appendf (&out, "xom reads %s (%lu)\n",
		!s->conn.framed? "not available (legacy server)"
		: s->memdump_cmd < 0? "not available (server has no memdump)"
		: s->memdump_cmd > 0? "server /proc/<pid>/mem": "server /proc/<pid>/mem (not used yet)",
		s->n_proc_reads);
	rn_buf_appendf (&out, "cache     %d ms\n", s->cache_ttl_ms);
	rn_buf_appendf (&out, "maps      %s, %d ranges, %d modules%s\n",
		s->maps_mode == RN_MAPS_RANGES? "ranges": "full", (int)s->n_ranges, (int)s->n_modules,
		s->maps_applied? ", applied": "");
	rn_buf_appendf (&out, "requests  %lu, %llu bytes received, timeout %d s\n", s->conn.n_requests,
		s->conn.rx_bytes, s->conn.timeout_ms / 1000);
	rn_buf_appendf (&out, "hooks     %d set with :hook\n", (int)s->n_hooks);
	return finish (&out);
}

static char *cmd_cache(RenefSession *s, const char *args) {
	RnBuf out;
	rn_buf_init (&out);
	if (!strcmp (args, "flush")) {
		rn_cache_flush (s);
	} else if (*args) {
		char *end = NULL;
		long ms = strtol (args, &end, 10);
		if (!end || *end || ms < 0 || ms > 3600000) {
			rn_buf_puts (&out, "usage: :cache [flush|<milliseconds, 0 = off>]\n");
			return finish (&out);
		}
		s->cache_ttl_ms = (int)ms;
		rn_cache_flush (s);
	}
	rn_buf_appendf (&out, "cache lifetime %d ms\n", s->cache_ttl_ms);
	return finish (&out);
}

static char *cmd_watch(RenefSession *s, const char *args) {
	int max_ms = 0;
	if (*args) {
		char *end = NULL;
		double secs = strtod (args, &end);
		if (!end || *end || secs <= 0 || secs > 86400) {
			return strdup ("usage: :watch [seconds]\n");
		}
		max_ms = (int)(secs * 1000);
		if (max_ms < 1) {
			max_ms = 1;
		}
	}
	return run_stream (s, "watch", max_ms);
}

/* ---- dispatch ---- */

static char *dispatch(RenefSession *s, const char *cmd) {
	cmd = skip_ws (cmd);
	if (!rn_conn_is_open (&s->conn)) {
		return strdup ("renef: not connected (the server closed the connection)\n");
	}
	/* name: up to the first blank; a trailing '*' selects r2 commands */
	const char *e = cmd;
	while (*e && *e != ' ' && *e != '\t') {
		e++;
	}
	const char *args = skip_ws (e);
	size_t nl = (size_t)(e - cmd);
	bool star = nl > 1 && cmd[nl - 1] == '*';
	if (star) {
		nl--;
	}
#define IS(name) (nl == sizeof (name) - 1 && !memcmp (cmd, name, nl))
	if (IS ("watch") && !star) {
		return cmd_watch (s, args);
	}
	if (IS ("?") || IS ("help")) {
		return strdup (HELP);
	}
	if (IS ("raw") && !star) {
		return *args? passthrough (s, args, true): strdup ("usage: :raw <command>\n");
	}
	if (IS ("info") && !star) {
		return cmd_info (s);
	}
	if (IS ("l") && !star) {
		return cmd_load (s, args);
	}
	if (IS ("sync") && !star) {
		return rn_cmd_sync (s, args);
	}
	if (IS ("dm")) {
		return rn_cmd_dm (s, args, star);
	}
	if (IS ("il") || IS ("dmm")) {
		return rn_cmd_modules (s, args, star);
	}
	if (IS ("ie")) {
		return rn_cmd_symbols (s, args, star, false);
	}
	if (IS ("is")) {
		return rn_cmd_symbols (s, args, star, true);
	}
	if (IS ("hook") && !star) {
		return cmd_hook (s, args);
	}
	if (IS ("hooks") && !star) {
		return cmd_hooks (s);
	}
	if (IS ("unhook") && !star) {
		return cmd_unhook (s, args);
	}
	if (IS ("jc") && !star) {
		return rn_cmd_jc (s, args);
	}
	if (IS ("jm") && !star) {
		return rn_cmd_jm (s, args);
	}
	if (IS ("jhook") && !star) {
		return rn_cmd_jhook (s, args);
	}
	if (IS ("jni") && !star) {
		return rn_cmd_jni (s, args);
	}
	if (IS ("jcode") && !star) {
		return rn_cmd_jcode (s, args);
	}
	if (IS ("hookgen") && !star) {
		return cmd_hookgen (s, args);
	}
	if (IS ("bt")) {
		return cmd_bt (s, args, star);
	}
	if (IS ("strace") && !star) {
		return cmd_strace (s, args);
	}
	if (IS ("/x")) {
		return cmd_search (s, args, true, star);
	}
	if (IS ("/")) {
		return cmd_search (s, args, false, star);
	}
	if (IS ("cache") && !star) {
		return cmd_cache (s, args);
	}
#undef IS
	return passthrough (s, cmd, false);
}

char *rn_command(RenefSession *s, const char *cmd) {
	cmd = skip_ws (cmd);
	bool watch = !strncmp (cmd, "watch", 5) && (!cmd[5] || cmd[5] == ' ');
	/* what the target printed on its own goes to stderr around the
	 * command (watch shows it itself), never into the command's output */
	if (!watch) {
		async_flush (s);
	}
	char *res = dispatch (s, cmd);
	if (!watch && rn_conn_is_open (&s->conn)) {
		async_flush (s);
	}
	/* Hook and trace output is not part of replies any more: the server
	 * keeps it until :watch asks. Say that some is waiting, under the
	 * command's own output - but not where that output is radare2
	 * commands (the * forms, run as .:cmd*). */
	unsigned long pending = s->conn.framed? s->conn.reader.pending_events: 0;
	const char *tok_end = cmd;
	while (*tok_end && *tok_end != ' ') {
		tok_end++;
	}
	bool star = tok_end > cmd && tok_end[-1] == '*';
	if (pending > 0 && !watch && !star && rn_conn_is_open (&s->conn)) {
		char *note = r_str_newf ("%s%s(%lu line%s of hook output waiting, :watch shows %s)\n",
			res? res: "", (res && *res && res[strlen (res) - 1] != '\n')? "\n": "",
			pending, pending == 1? "": "s", pending == 1? "it": "them");
		if (note) {
			free (res);
			res = note;
		}
	}
	return res;
}
