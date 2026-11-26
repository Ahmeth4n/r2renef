/* r2renef - MIT - Copyright 2025-2026 */

#include "renef_java.h"
#include "renef_java_lua.h"
#include "renef_maps.h"
#include "renef_session.h"

#include <r_util.h>

/* must be the VERSION of src/renef_java.lua */
#define RN_JAVA_VERSION 2
#define RN_JC_DEFAULT 200
#define RN_JAVA_MAX_TYPES 32

/* ---- small helpers ---- */

static const char *skip_ws(const char *p) {
	while (*p == ' ' || *p == '\t') {
		p++;
	}
	return p;
}

/* Copies the next token and advances *p past it. A token that starts with
 * a double quote runs to the closing one (\" and \\ are unescaped). */
static char *take_token(const char **p) {
	const char *s = skip_ws (*p);
	if (*s == '"') {
		RnBuf b;
		rn_buf_init (&b);
		s++;
		while (*s && *s != '"') {
			if (*s == '\\' && (s[1] == '"' || s[1] == '\\')) {
				s++;
			}
			rn_buf_append (&b, s, 1);
			s++;
		}
		*p = skip_ws (*s? s + 1: s);
		char *res = rn_buf_steal (&b, NULL);
		return res? res: strdup ("");
	}
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

/* ---- running a function of the Lua side ---- */

typedef struct {
	RnLineCb cb;
	void *user;
	bool need_load;
	bool loaded;
} JavaScan;

static void java_line(void *user, const char *line, size_t len) {
	JavaScan *js = user;
	if (len >= 1 && line[0] == 'P') {
		js->need_load = true;
	} else if (len >= 1 && line[0] == 'L') {
		js->loaded = true;
	} else if (js->cb) {
		js->cb (js->user, line, len);
	}
}

/* Runs `call` (Lua that uses __r2j) in the target and hands every tagged
 * line to `cb`. The Lua side is sent first if the target does not have it:
 * a fresh session, or an app that was spawned again. Untagged lines of the
 * reply (hook output that arrived in between) go to `other`. */
static RnStatus java_run_for(RenefSession *s, const char *call, int timeout_ms, RnLineCb cb, void *user, RnBuf *other, RnBuf *err) {
	RnBuf lua, reply;
	JavaScan js = { cb, user, false, false };
	bool failed = false;
	RnStatus st;
	int attempt;

	rn_buf_init (&lua);
	rn_buf_init (&reply);
	if (!rn_buf_appendf (&lua, "if not __r2j or __r2j.version~=%d then print('" RN_TAG "P') return end ", RN_JAVA_VERSION)
		|| !rn_buf_puts (&lua, call)) {
		rn_buf_fini (&lua);
		return RN_ERROR;
	}
	for (attempt = 0; attempt < 2; attempt++) {
		js.need_load = false;
		rn_buf_clear (&reply);
		st = rn_exec (s, lua.data, timeout_ms, &reply);
		if (st != RN_OK) {
			break;
		}
		rn_scan_reply (s, &reply, java_line, &js, other, &failed);
		if (!js.need_load) {
			break;
		}
		if (attempt == 1) {
			rn_buf_puts (err, "the Java helper did not stay loaded in the target\n");
			st = RN_ERROR;
			break;
		}
		rn_buf_clear (&reply);
		js.loaded = false;
		st = rn_exec (s, rn_java_lua, 0, &reply);
		if (st != RN_OK) {
			break;
		}
		{
			RnBuf why;
			rn_buf_init (&why);
			rn_scan_reply (s, &reply, java_line, &js, &why, &failed);
			if (!js.loaded) {
				rn_buf_puts (err, "could not load the Java helper into the target");
				if (why.len) {
					rn_buf_puts (err, ": ");
					rn_buf_append (err, why.data, why.len);
				} else {
					rn_buf_puts (err, " (does this renef have the Java API?)\n");
				}
				rn_buf_fini (&why);
				st = RN_ERROR;
				break;
			}
			rn_buf_fini (&why);
		}
	}
	if (st != RN_OK && !err->len) {
		rn_buf_appendf (err, "renef: %s\n", rn_status_str (st));
	} else if (st == RN_OK && failed && !err->len) {
		rn_buf_puts (err, "the script failed in the target (adb logcat -s RENEF_AGENT shows why)\n");
	}
	rn_buf_fini (&lua);
	rn_buf_fini (&reply);
	return st;
}

static RnStatus java_run(RenefSession *s, const char *call, RnLineCb cb, void *user, RnBuf *other, RnBuf *err) {
	return java_run_for (s, call, 0, cb, user, other, err);
}

/* A tagged line is "<kind> <field>\t<field>...". Returns the kind and
 * splits the rest in place: at most `max` fields. */
static int split_line(char *line, char **fields, int max) {
	int n = 0;
	char *p = line + 1;
	if (*p == ' ') {
		p++;
	}
	while (n < max) {
		fields[n++] = p;
		char *tab = strchr (p, '\t');
		if (!tab) {
			break;
		}
		*tab = '\0';
		p = tab + 1;
	}
	return n;
}

/* ---- :jc ---- */

typedef struct {
	RnBuf *out;
	long shown;
	long hits;
	long total;
	char err[256];
} ListCtx;

static void jc_line(void *user, const char *line, size_t len) {
	ListCtx *ctx = user;
	char *copy = r_str_ndup (line, (int)len);
	char *f[2];
	if (!copy) {
		return;
	}
	int n = split_line (copy, f, 2);
	if (copy[0] == 'C' && n >= 1) {
		rn_buf_appendf (ctx->out, "%s\n", f[0]);
		ctx->shown++;
	} else if (copy[0] == 'N' && n >= 2) {
		ctx->hits = atol (f[0]);
		ctx->total = atol (f[1]);
	} else if (copy[0] == 'E' && n >= 1) {
		snprintf (ctx->err, sizeof (ctx->err), "%s", f[0]);
	}
	free (copy);
}

char *rn_cmd_jc(RenefSession *s, const char *args) {
	RnBuf out, lua, err;
	ListCtx ctx;
	const char *p = skip_ws (args);
	long limit = RN_JC_DEFAULT;
	char *filter = NULL;

	rn_buf_init (&out);
	rn_buf_init (&lua);
	rn_buf_init (&err);
	memset (&ctx, 0, sizeof (ctx));
	ctx.out = &out;
	while (*p) {
		char *tok = take_token (&p);
		if (!tok) {
			break;
		}
		if (!strcmp (tok, "-n")) {
			char *num = take_token (&p);
			limit = num? atol (num): 0;
			free (num);
			if (limit <= 0) {
				free (tok);
				rn_buf_puts (&out, "usage: :jc [-n <max>] [filter]\n");
				goto done;
			}
		} else if (!strcmp (tok, "-h") || !strcmp (tok, "?")) {
			free (tok);
			rn_buf_puts (&out, "usage: :jc [-n <max>] [filter]   classes of the app whose name contains <filter>\n");
			goto done;
		} else {
			free (filter);
			filter = strdup (tok);
		}
		free (tok);
	}
	if (!rn_buf_puts (&lua, "__r2j.classes(")
		|| !rn_lua_quote (&lua, filter? filter: "", filter? strlen (filter): 0)
		|| !rn_buf_appendf (&lua, ",%ld)", limit)) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}
	if (java_run (s, lua.data, jc_line, &ctx, NULL, &err) != RN_OK || err.len) {
		rn_buf_clear (&out);
		rn_buf_append (&out, err.data, err.len);
		goto done;
	}
	if (*ctx.err) {
		rn_buf_appendf (&out, "%s\n", ctx.err);
	} else if (!ctx.total) {
		rn_buf_puts (&out, "the app's class loader lists no classes (is the app fully started?)\n");
	} else if (ctx.hits > ctx.shown) {
		rn_buf_appendf (&out, "%ld of %ld matching classes shown (%ld in the app): narrow the filter or :jc -n %ld %s\n",
			ctx.shown, ctx.hits, ctx.total, ctx.hits, filter? filter: "");
	} else if (filter) {
		rn_buf_appendf (&out, "%ld of the app's %ld classes match\n", ctx.hits, ctx.total);
	} else {
		rn_buf_appendf (&out, "%ld classes in the app's own dex files (framework classes are not listed: name them in :jm)\n",
			ctx.total);
	}
done:
	free (filter);
	rn_buf_fini (&lua);
	rn_buf_fini (&err);
	return finish (&out);
}

/* ---- :jm ---- */

typedef struct {
	RnBuf *out;
	bool sigs;
	long count;
	long hidden;
	RnBuf candidates;       /* choices that belong under the error message */
	char err[256];
} MemberCtx;

static void jm_line(void *user, const char *line, size_t len) {
	MemberCtx *ctx = user;
	char *copy = r_str_ndup (line, (int)len);
	char *f[2];
	if (!copy) {
		return;
	}
	int n = split_line (copy, f, 2);
	switch (copy[0]) {
	case 'H':
		rn_buf_appendf (ctx->out, "%s\n", f[0]);
		break;
	case 'M':
		if (ctx->sigs && n >= 2) {
			rn_buf_appendf (ctx->out, "  %-56s %s\n", f[0], f[1]);
		} else {
			rn_buf_appendf (ctx->out, "  %s\n", f[0]);
		}
		break;
	case 'A':
		rn_buf_appendf (&ctx->candidates, "  %s\n", f[0]);
		break;
	case 'N':
		ctx->count = atol (f[0]);
		ctx->hidden = n >= 2? atol (f[1]): 0;
		break;
	case 'E':
		snprintf (ctx->err, sizeof (ctx->err), "%s", f[0]);
		break;
	}
	free (copy);
}

char *rn_cmd_jm(RenefSession *s, const char *args) {
	static const char usage[] =
		"usage: :jm [-s] [-a] <class> [filter]\n"
		"  methods and constructors of a class; the short name is enough when it is unique\n"
		"  -s  also print the JNI signature     -a  also list compiler-made methods\n";
	RnBuf out, lua, err;
	MemberCtx ctx;
	const char *p = skip_ws (args);
	char *cls = NULL, *filter = NULL;
	bool all = false;

	rn_buf_init (&out);
	rn_buf_init (&lua);
	rn_buf_init (&err);
	memset (&ctx, 0, sizeof (ctx));
	ctx.out = &out;
	rn_buf_init (&ctx.candidates);
	while (*p) {
		char *tok = take_token (&p);
		if (!tok) {
			break;
		}
		if (!strcmp (tok, "-s")) {
			ctx.sigs = true;
		} else if (!strcmp (tok, "-a")) {
			all = true;
		} else if (!cls) {
			cls = strdup (tok);
		} else {
			free (filter);
			filter = strdup (tok);
		}
		free (tok);
	}
	if (!cls || !strcmp (cls, "-h") || !strcmp (cls, "?")) {
		rn_buf_puts (&out, usage);
		goto done;
	}
	if (!rn_buf_puts (&lua, "__r2j.members(") || !rn_lua_quote (&lua, cls, strlen (cls))
		|| !rn_buf_puts (&lua, ",") || !rn_lua_quote (&lua, filter? filter: "", filter? strlen (filter): 0)
		|| !rn_buf_appendf (&lua, ",%s)", all? "true": "false")) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}
	if (java_run (s, lua.data, jm_line, &ctx, NULL, &err) != RN_OK || err.len) {
		rn_buf_clear (&out);
		rn_buf_append (&out, err.data, err.len);
		goto done;
	}
	if (*ctx.err) {
		rn_buf_appendf (&out, "%s\n", ctx.err);
		rn_buf_append (&out, ctx.candidates.data, ctx.candidates.len);
	} else if (ctx.hidden) {
		rn_buf_appendf (&out, "%ld listed, %ld compiler-made not shown (-a)\n", ctx.count, ctx.hidden);
	} else if (!ctx.count) {
		rn_buf_puts (&out, filter? "no method matches the filter\n": "the class declares no methods\n");
	}
done:
	free (cls);
	free (filter);
	rn_buf_fini (&ctx.candidates);
	rn_buf_fini (&lua);
	rn_buf_fini (&err);
	return finish (&out);
}

/* ---- :jhook ---- */

#define RN_JHOOK_MAX 64

typedef struct {
	char *key;      /* "a/b/C.method(sig)ret", as the agent lists the hook */
	char *text;     /* "boolean check(String)" */
	char id[16];    /* "j3", from the agent's listing */
	char guess[16]; /* the number the Lua side printed with so far */
} JHook;

typedef struct {
	RnBuf *out;
	JHook done[RN_JHOOK_MAX];
	int n_done;
	int n_failed;
	RnBuf candidates;
	char err[256];
} JHookCtx;

static void jhook_line(void *user, const char *line, size_t len) {
	JHookCtx *ctx = user;
	char *copy = r_str_ndup (line, (int)len);
	char *f[3];
	if (!copy) {
		return;
	}
	int n = split_line (copy, f, 3);
	switch (copy[0]) {
	case 'K':
		if (n >= 2 && ctx->n_done < RN_JHOOK_MAX) {
			JHook *h = &ctx->done[ctx->n_done++];
			h->key = strdup (f[0]);
			h->text = strdup (f[1]);
			h->id[0] = '\0';
			snprintf (h->guess, sizeof (h->guess), "%s", n >= 3? f[2]: "");
		}
		break;
	case 'F':
		rn_buf_appendf (ctx->out, "not hooked: %s\n  %s\n", f[0], n >= 2? f[1]: "");
		ctx->n_failed++;
		break;
	case 'A':
		rn_buf_appendf (&ctx->candidates, "  %s\n", f[0]);
		break;
	case 'E':
		snprintf (ctx->err, sizeof (ctx->err), "%s", f[0]);
		break;
	}
	free (copy);
}

/* Number the agent will give its next Java hook: they are numbered in the
 * order they are made and a number is never used twice, so it is the
 * count of "[jN]" lines in the `hooks` listing (which has no Java part
 * while there is no Java hook). -1 without an answer. */
static int jhook_next_id(RenefSession *s) {
	RnBuf reply;
	int n = -1;
	rn_buf_init (&reply);
	if (rn_conn_request (&s->conn, "hooks", 5, RN_END_QUIET, 0, &reply) == RN_OK && reply.data
		&& strstr (reply.data, "Active hooks:")) {
		const char *p = reply.data;
		n = 0;
		while ((p = strstr (p, "[j"))) {
			if (p[2] >= '0' && p[2] <= '9') {
				n++;
			}
			p += 2;
		}
	}
	rn_buf_fini (&reply);
	return n;
}

/* Takes "[jN]" for each new hook from the agent's `hooks` listing, whose
 * Java lines read "  [jN] a/b/C.method(sig)ret hits=M". */
static void jhook_ids(RenefSession *s, JHookCtx *ctx) {
	RnBuf reply;
	rn_buf_init (&reply);
	if (rn_conn_request (&s->conn, "hooks", 5, RN_END_QUIET, 0, &reply) == RN_OK && reply.data) {
		const char *p = reply.data;
		while (p && *p) {
			const char *nl = strchr (p, '\n');
			const char *lb = strstr (p, "[j");
			if (lb && (!nl || lb < nl)) {
				const char *rb = strchr (lb, ']');
				if (rb && (!nl || rb < nl) && rb[1] == ' ') {
					const char *key = rb + 2;
					const char *end = strstr (key, " hits=");
					if (!end || (nl && end > nl)) {
						end = nl? nl: key + strlen (key);
					}
					int i;
					for (i = 0; i < ctx->n_done; i++) {
						JHook *h = &ctx->done[i];
						if (h->key && strlen (h->key) == (size_t)(end - key) && !memcmp (h->key, key, (size_t)(end - key))) {
							size_t n = (size_t)(rb - lb - 1);
							if (n < sizeof (h->id)) {
								memcpy (h->id, lb + 1, n);
								h->id[n] = '\0';
							}
						}
					}
				}
			}
			p = nl? nl + 1: NULL;
		}
	}
	rn_buf_fini (&reply);
}

/* "(String, int)" -> Lua "{'String','int'}"; false on a missing ')' */
static bool parse_types(const char **pp, RnBuf *lua, RnBuf *out) {
	const char *p = *pp + 1;
	const char *close = strchr (p, ')');
	int n = 0;
	if (!close) {
		rn_buf_puts (out, "the parameter list has no closing ')'\n");
		return false;
	}
	rn_buf_puts (lua, "types={");
	while (p < close) {
		while (p < close && (*p == ' ' || *p == '\t' || *p == ',')) {
			p++;
		}
		const char *e = p;
		while (e < close && *e != ',') {
			e++;
		}
		const char *t = e;
		while (t > p && (t[-1] == ' ' || t[-1] == '\t')) {
			t--;
		}
		if (t > p) {
			if (++n > RN_JAVA_MAX_TYPES) {
				rn_buf_puts (out, "too many parameter types\n");
				return false;
			}
			rn_lua_quote (lua, p, (size_t)(t - p));
			rn_buf_puts (lua, ",");
		}
		p = e;
	}
	rn_buf_puts (lua, "},");
	*pp = skip_ws (close + 1);
	return true;
}

char *rn_cmd_jhook(RenefSession *s, const char *args) {
	static const char usage[] =
		"usage: :jhook <class> <method> [(types)] [-r <value>] [-k] [-b] [-n <N>] [-s] [-a] [-e <lua>]\n"
		"  hooks a Java method and logs its calls (:watch shows them); without (types)\n"
		"  every method of that name is hooked. <method> `new` is the constructor.\n"
		"  (types)      pick one overload, written as in Java: (String, int)   () = no parameters\n"
		"  -r <value>   return this instead: true/false, a number, \"text\" or null\n"
		"  -k           do not run the original (with -r: return that value; else 0/null)\n"
		"  -b           log the Java stack on every call\n"
		"  -n <N>       stop printing after N calls (the hook stays and keeps counting)\n"
		"  -s           print objects with toString() and the receiver of the call\n"
		"  -a           also hook compiler-made twins of the method\n"
		"  -e <lua>     body of onEnter(args) instead of the logger\n";
	RnBuf out, lua, err;
	JHookCtx ctx;
	const char *p = skip_ws (args);
	char *cls = NULL, *method = NULL;
	int i;

	rn_buf_init (&out);
	rn_buf_init (&lua);
	rn_buf_init (&err);
	memset (&ctx, 0, sizeof (ctx));
	ctx.out = &out;
	rn_buf_init (&ctx.candidates);

	cls = *p? take_token (&p): NULL;
	if (cls && *p && *p != '-' && *p != '(') {
		/* the method name ends at a blank or at the '(' of the types */
		const char *e = p;
		while (*e && *e != ' ' && *e != '\t' && *e != '(') {
			e++;
		}
		method = r_str_ndup (p, (int)(e - p));
		p = skip_ws (e);
	}
	if (!cls || !method || !*method || !strcmp (cls, "-h") || !strcmp (cls, "?")) {
		rn_buf_puts (&out, usage);
		goto done;
	}
	if (!rn_buf_puts (&lua, "__r2j.hook(") || !rn_lua_quote (&lua, cls, strlen (cls))
		|| !rn_buf_puts (&lua, ",") || !rn_lua_quote (&lua, method, strlen (method))
		|| !rn_buf_puts (&lua, ",{")) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}
	if (*p == '(' && !parse_types (&p, &lua, &out)) {
		goto done;
	}
	while (*p) {
		if (!strncmp (p, "-e ", 3)) {
			const char *body = skip_ws (p + 3);
			rn_buf_puts (&lua, "body=");
			rn_lua_quote (&lua, body, strlen (body));
			rn_buf_puts (&lua, ",");
			break;
		}
		char *tok = take_token (&p);
		if (!tok) {
			break;
		}
		bool bad = false;
		if (!strcmp (tok, "-k")) {
			rn_buf_puts (&lua, "skip=true,");
		} else if (!strcmp (tok, "-b")) {
			rn_buf_puts (&lua, "bt=true,");
		} else if (!strcmp (tok, "-s")) {
			rn_buf_puts (&lua, "deep=true,");
		} else if (!strcmp (tok, "-a")) {
			rn_buf_puts (&lua, "all=true,");
		} else if (!strcmp (tok, "-r") && *p) {
			char *val = take_token (&p);
			rn_buf_puts (&lua, "ret=");
			rn_lua_quote (&lua, val? val: "", val? strlen (val): 0);
			rn_buf_puts (&lua, ",");
			free (val);
		} else if (!strcmp (tok, "-n") && *p) {
			char *num = take_token (&p);
			long limit = num? atol (num): 0;
			free (num);
			if (limit > 0) {
				rn_buf_appendf (&lua, "limit=%ld,", limit);
			} else {
				bad = true;
			}
		} else {
			bad = true;
		}
		if (bad) {
			rn_buf_appendf (&out, "unexpected '%s'\n%s", tok, usage);
			free (tok);
			goto done;
		}
		free (tok);
	}
	{
		int first = jhook_next_id (s);
		if (first >= 0) {
			rn_buf_appendf (&lua, "first=%d,", first);
		}
	}
	if (!rn_buf_puts (&lua, "})")) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}
	if (java_run (s, lua.data, jhook_line, &ctx, NULL, &err) != RN_OK || err.len) {
		rn_buf_clear (&out);
		rn_buf_append (&out, err.data, err.len);
		goto done;
	}
	if (*ctx.err) {
		rn_buf_appendf (&out, "%s\n", ctx.err);
		rn_buf_append (&out, ctx.candidates.data, ctx.candidates.len);
		goto done;
	}
	if (ctx.n_done) {
		RnBuf bind;
		rn_buf_init (&bind);
		jhook_ids (s, &ctx);
		for (i = 0; i < ctx.n_done; i++) {
			JHook *h = &ctx.done[i];
			/* the listing decides; a server that does not list Java
			 * hooks (renef before 0.4.0) leaves the number unknown */
			if (strcmp (h->id, h->guess)) {
				rn_buf_puts (&bind, "__r2j.bind(");
				rn_lua_quote (&bind, h->key, strlen (h->key));
				rn_buf_puts (&bind, ",");
				rn_lua_quote (&bind, h->id, strlen (h->id));
				rn_buf_puts (&bind, ") ");
			}
			if (*h->id) {
				rn_buf_appendf (&out, "hook %s installed: %s\n", h->id, h->text);
			} else {
				rn_buf_appendf (&out, "hook installed: %s\n", h->text);
			}
		}
		if (bind.len && rn_buf_puts (&bind, "print('" RN_TAG "B')")) {
			RnBuf ignore;
			rn_buf_init (&ignore);
			rn_buf_clear (&err);
			java_run (s, bind.data, NULL, NULL, &ignore, &err);
			rn_buf_fini (&ignore);
		}
		rn_buf_fini (&bind);
		rn_buf_puts (&out, "output is asynchronous: :watch follows it, :unhook <jN> removes a hook\n");
	} else if (!ctx.n_failed) {
		rn_buf_puts (&out, "nothing was hooked\n");
	}
done:
	for (i = 0; i < ctx.n_done; i++) {
		free (ctx.done[i].key);
		free (ctx.done[i].text);
	}
	free (cls);
	free (method);
	rn_buf_fini (&ctx.candidates);
	rn_buf_fini (&lua);
	rn_buf_fini (&err);
	return finish (&out);
}

/* ---- :jni / :jcode: from a Java method to its code ---- */

#define RN_JNI_SCAN_MS 120000

/* "sym.jni.PinManager_check": the class without its package, made unique
 * among the flags set by this command (overloads get _2, _3 ...). */
static char *code_flag(const char *prefix, const char *cls, const char *method, RnBuf *used) {
	const char *shortc = strrchr (cls, '.');
	shortc = shortc? shortc + 1: cls;
	char *raw = r_str_newf ("%s_%s", shortc, !strcmp (method, "<init>")? "new": method);
	char *clean = raw? rn_flag_name (raw): NULL;
	char *name = NULL;
	int n;
	free (raw);
	if (!clean) {
		return NULL;
	}
	for (n = 1; n < 1000; n++) {
		free (name);
		name = n == 1? r_str_newf ("%s%s", prefix, clean): r_str_newf ("%s%s_%d", prefix, clean, n);
		if (!name) {
			break;
		}
		char *probe = r_str_newf ("\n%s\n", name);
		bool taken = probe && used->data && strstr (used->data, probe);
		free (probe);
		if (!taken) {
			if (!used->len) {
				rn_buf_puts (used, "\n");
			}
			rn_buf_appendf (used, "%s\n", name);
			break;
		}
	}
	free (clean);
	return name;
}

typedef struct {
	RenefSession *s;
	RnBuf *out;
	RnBuf used;
	bool flags;
	long found;
	long classes;
	long bound;
	long by_export;
	long unbound;
	char last_class[256];
	char err[256];
} JniCtx;

static void jni_line(void *user, const char *line, size_t len) {
	JniCtx *ctx = user;
	char *copy = r_str_ndup (line, (int)len);
	char *f[5];
	if (!copy) {
		return;
	}
	int n = split_line (copy, f, 5);
	if (copy[0] == 'J' && n >= 5) {
		ut64 addr = strtoull (f[0], NULL, 16);
		char *label = rn_addr_label (ctx->s, addr);
		const RnModule *mod = rn_module_at (ctx->s, addr);
		char state = f[1][0];
		/* an agent that cannot tell ("?") leaves the address: for an
		 * app's own methods a function inside libart is the lookup stub */
		if (state == '?') {
			state = (mod && !strcmp (mod->name, "libart.so"))? '0': '1';
		}
		if (strcmp (ctx->last_class, f[2])) {
			snprintf (ctx->last_class, sizeof (ctx->last_class), "%s", f[2]);
			rn_buf_appendf (ctx->out, "%s\n", f[2]);
		}
		if (state == '0') {
			rn_buf_appendf (ctx->out, "  %-14s %-28s %s\n", "not bound", "", f[4]);
			ctx->unbound++;
		} else {
			char *flag = ctx->flags? code_flag ("sym.jni.", f[2], f[3], &ctx->used): NULL;
			if (flag && rn_r2_available (ctx->s)) {
				rn_r2cmdf (ctx->s, "f %s 1 0x%" PFMT64x, flag, addr);
			}
			rn_buf_appendf (ctx->out, "  0x%-12" PFMT64x " %-28s %s%s\n", addr, label? label: "?", f[4],
				state == 'e'? "   (not bound yet: by its export name)": "");
			if (flag) {
				rn_buf_appendf (ctx->out, "  %-14s %s\n", "", flag);
			}
			free (flag);
			if (state == 'e') {
				ctx->by_export++;
			} else {
				ctx->bound++;
			}
		}
		free (label);
	} else if (copy[0] == 'N' && n >= 2) {
		ctx->found = atol (f[0]);
		ctx->classes = atol (f[1]);
	} else if (copy[0] == 'A' && n >= 1) {
		rn_buf_appendf (ctx->out, "  %s\n", f[0]);
	} else if (copy[0] == 'E' && n >= 1) {
		snprintf (ctx->err, sizeof (ctx->err), "%s", f[0]);
	}
	free (copy);
}

char *rn_cmd_jni(RenefSession *s, const char *args) {
	static const char usage[] =
		"usage: :jni [-n] <class>         native methods of a class and the functions they run\n"
		"       :jni [-n] -a [filter]     the same for every class of the app (name contains <filter>)\n"
		"  each function gets a flag sym.jni.<Class>_<method> (-n: no flags). A method that is\n"
		"  not bound yet is looked up by its JNI export name in the app's libraries.\n";
	RnBuf out, lua, err, body;
	JniCtx ctx;
	const char *p = skip_ws (args);
	char *name = NULL;
	bool all = false;

	rn_buf_init (&out);
	rn_buf_init (&lua);
	rn_buf_init (&err);
	rn_buf_init (&body);
	memset (&ctx, 0, sizeof (ctx));
	ctx.s = s;
	ctx.out = &body;
	ctx.flags = true;
	rn_buf_init (&ctx.used);
	while (*p) {
		char *tok = take_token (&p);
		if (!tok) {
			break;
		}
		if (!strcmp (tok, "-a")) {
			all = true;
		} else if (!strcmp (tok, "-n")) {
			ctx.flags = false;
		} else if (!name && strcmp (tok, "-h") && strcmp (tok, "?")) {
			name = strdup (tok);
		} else {
			free (tok);
			free (name);
			name = NULL;
			all = false;
			break;
		}
		free (tok);
	}
	if (!name && !all) {
		rn_buf_puts (&out, usage);
		goto done;
	}
	rn_ranges_ensure (s, NULL);
	if (!rn_buf_puts (&lua, "__r2j.natives(") || !rn_lua_quote (&lua, name? name: "", name? strlen (name): 0)
		|| !rn_buf_appendf (&lua, ",%s,{", all? "true": "false")) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}
	{
		/* the app's own libraries: where a method that is not bound yet
		 * is looked up by its JNI export name */
		size_t i;
		int n = 0;
		for (i = 0; i < s->n_modules && n < 64; i++) {
			const RnModule *m = &s->modules[i];
			if (m->path && (!strncmp (m->path, "/data/", 6) || !strncmp (m->path, "/mnt/", 5))
				&& strstr (m->name, ".so") && strcmp (m->name, "libagent.so")) {
				const char *ln = rn_module_luaname (m);
				rn_lua_quote (&lua, ln, strlen (ln));
				rn_buf_puts (&lua, ",");
				n++;
			}
		}
	}
	if (!rn_buf_puts (&lua, "})")) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}
	if (java_run_for (s, lua.data, all? RN_JNI_SCAN_MS: 0, jni_line, &ctx, NULL, &err) != RN_OK || err.len) {
		rn_buf_append (&out, err.data, err.len);
		goto done;
	}
	if (*ctx.err) {
		rn_buf_appendf (&out, "%s\n", ctx.err);
		rn_buf_append (&out, body.data, body.len);
		goto done;
	}
	rn_buf_append (&out, body.data, body.len);
	if (!ctx.found) {
		if (all) {
			rn_buf_appendf (&out, "no native methods in the %ld classes looked at\n", ctx.classes);
		} else {
			rn_buf_puts (&out, "the class declares no native methods\n");
		}
	} else {
		rn_buf_appendf (&out, "%ld native method%s", ctx.found, ctx.found == 1? "": "s");
		if (all) {
			rn_buf_appendf (&out, " in %ld classes", ctx.classes);
		}
		rn_buf_appendf (&out, ": %ld bound", ctx.bound);
		if (ctx.by_export) {
			rn_buf_appendf (&out, ", %ld found by export name", ctx.by_export);
		}
		if (ctx.unbound) {
			rn_buf_appendf (&out, ", %ld not bound yet (no function until the library is loaded or registers them)",
				ctx.unbound);
		}
		rn_buf_puts (&out, "\n");
	}
done:
	free (name);
	rn_buf_fini (&ctx.used);
	rn_buf_fini (&body);
	rn_buf_fini (&lua);
	rn_buf_fini (&err);
	return finish (&out);
}

typedef struct {
	RenefSession *s;
	RnBuf *out;
	RnBuf used;
	RnBuf candidates;
	int shown;
	ut64 seek;
	char err[256];
} CodeCtx;

static void code_line(void *user, const char *line, size_t len) {
	CodeCtx *ctx = user;
	char *copy = r_str_ndup (line, (int)len);
	char *f[6];
	if (!copy) {
		return;
	}
	int n = split_line (copy, f, 6);
	if (copy[0] == 'X' && n >= 6) {
		ut64 entry = strtoull (f[0], NULL, 16);
		ut64 jni = strtoull (f[1], NULL, 16);
		bool hooked = f[2][0] == '1';
		ut64 addr = jni? jni: entry;
		const RnModule *mod = rn_module_at (ctx->s, addr);
		const RnRange *range = rn_range_at (ctx->s, addr);
		char *label = rn_addr_label (ctx->s, addr);
		bool in_art = mod && !strcmp (mod->name, "libart.so");
		rn_buf_appendf (ctx->out, "%s   (%s%s)\n", f[5], f[3], hooked? ", hooked": "");
		if (in_art && jni) {
			rn_buf_puts (ctx->out, "  native, not bound to a function yet\n");
		} else if (in_art) {
			rn_buf_puts (ctx->out, "  no compiled code: it runs in ART's interpreter\n");
		} else {
			char *flag = code_flag (jni? "sym.jni.": "sym.java.", f[3], f[4], &ctx->used);
			if (flag && rn_r2_available (ctx->s)) {
				rn_r2cmdf (ctx->s, "f %s 1 0x%" PFMT64x, flag, addr);
			}
			rn_buf_appendf (ctx->out, "  %s at 0x%" PFMT64x " (%s)%s%s\n",
				jni? "native function": "compiled code", addr,
				mod? (label? label: mod->name): (range && range->path && *range->path? range->path: "anonymous memory"),
				flag? "  ": "", flag? flag: "");
			free (flag);
			if (!ctx->shown) {
				ctx->seek = addr;
			}
			ctx->shown++;
		}
		free (label);
	} else if (copy[0] == 'A' && n >= 1) {
		rn_buf_appendf (&ctx->candidates, "  %s\n", f[0]);
	} else if (copy[0] == 'E' && n >= 1) {
		snprintf (ctx->err, sizeof (ctx->err), "%s", f[0]);
	}
	free (copy);
}

char *rn_cmd_jcode(RenefSession *s, const char *args) {
	static const char usage[] =
		"usage: :jcode <class> <method> [(types)]\n"
		"  where the code of a Java method is: the compiled code ART runs for it, or for a\n"
		"  native method its function. Sets a flag and, when there is one answer, seeks\n"
		"  there - pd / pdf then show the code.\n";
	RnBuf out, lua, err, body;
	CodeCtx ctx;
	const char *p = skip_ws (args);
	char *cls = NULL, *method = NULL;

	rn_buf_init (&out);
	rn_buf_init (&lua);
	rn_buf_init (&err);
	rn_buf_init (&body);
	memset (&ctx, 0, sizeof (ctx));
	ctx.s = s;
	ctx.out = &body;
	rn_buf_init (&ctx.used);
	rn_buf_init (&ctx.candidates);

	cls = *p? take_token (&p): NULL;
	if (cls && *p && *p != '-' && *p != '(') {
		const char *e = p;
		while (*e && *e != ' ' && *e != '\t' && *e != '(') {
			e++;
		}
		method = r_str_ndup (p, (int)(e - p));
		p = skip_ws (e);
	}
	if (!cls || !method || !*method || !strcmp (cls, "-h") || !strcmp (cls, "?")) {
		rn_buf_puts (&out, usage);
		goto done;
	}
	if (!rn_buf_puts (&lua, "__r2j.code(") || !rn_lua_quote (&lua, cls, strlen (cls))
		|| !rn_buf_puts (&lua, ",") || !rn_lua_quote (&lua, method, strlen (method))
		|| !rn_buf_puts (&lua, ",")) {
		rn_buf_puts (&out, "out of memory\n");
		goto done;
	}
	if (*p == '(') {
		RnBuf types;
		rn_buf_init (&types);
		if (!parse_types (&p, &types, &out)) {
			rn_buf_fini (&types);
			goto done;
		}
		/* parse_types writes "types={...}," for an options table */
		if (types.len > 7) {
			rn_buf_append (&lua, types.data + 6, types.len - 7);
		}
		rn_buf_fini (&types);
	} else {
		rn_buf_puts (&lua, "nil");
	}
	if (*p) {
		rn_buf_appendf (&out, "unexpected '%s'\n%s", p, usage);
		goto done;
	}
	rn_buf_puts (&lua, ")");
	rn_ranges_ensure (s, NULL);
	if (java_run (s, lua.data, code_line, &ctx, NULL, &err) != RN_OK || err.len) {
		rn_buf_append (&out, err.data, err.len);
		goto done;
	}
	if (*ctx.err) {
		rn_buf_appendf (&out, "%s\n", ctx.err);
		rn_buf_append (&out, ctx.candidates.data, ctx.candidates.len);
		goto done;
	}
	rn_buf_append (&out, body.data, body.len);
	if (ctx.shown == 1 && rn_r2_available (s)) {
		rn_r2cmdf (s, "s 0x%" PFMT64x, ctx.seek);
	} else if (ctx.shown > 1) {
		rn_buf_puts (&out, "several methods: seek to the one you want (s <flag>), or pick it with (types)\n");
	}
done:
	free (cls);
	free (method);
	rn_buf_fini (&ctx.used);
	rn_buf_fini (&ctx.candidates);
	rn_buf_fini (&body);
	rn_buf_fini (&lua);
	rn_buf_fini (&err);
	return finish (&out);
}
