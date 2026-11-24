/* r2renef - MIT - Copyright 2025-2026 */

#include "renef_session.h"

#include <stdarg.h>
#include <time.h>

long long rn_now_ms(void) {
	struct timespec ts;
	clock_gettime (CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

RenefSession *rn_session_new(void) {
	RenefSession *s = calloc (1, sizeof (RenefSession));
	if (!s) {
		return NULL;
	}
	rn_conn_init (&s->conn);
	rn_buf_init (&s->async_tail);
	s->fd = -1;
	s->cache_ttl_ms = rn_env_int ("RENEF_CACHE_MS", 2000, 0, 3600000);
	s->autosync = rn_env_int ("RENEF_NOSYNC", 0, 0, 1) == 0;

	const char *rp = getenv ("RENEF_READ");
	s->read_path = RN_READ_AUTO;
	if (rp && !strcmp (rp, "md")) {
		s->read_path = RN_READ_MD;
	} else if (rp && !strcmp (rp, "lua")) {
		s->read_path = RN_READ_LUA;
	}
	s->lua_read_ok = s->read_path != RN_READ_MD;
	s->lua_read_checked = s->read_path == RN_READ_LUA;
	const char *mm = getenv ("RENEF_MAPS");
	s->maps_mode = (mm && !strcmp (mm, "full"))? RN_MAPS_FULL: RN_MAPS_RANGES;
	return s;
}

void rn_session_free(RenefSession *s) {
	size_t i;
	if (!s) {
		return;
	}
	rn_conn_fini (&s->conn);
	rn_buf_fini (&s->async_tail);
	for (i = 0; i < s->n_ranges; i++) {
		free (s->ranges[i].path);
	}
	free (s->ranges);
	for (i = 0; i < s->n_modules; i++) {
		free (s->modules[i].name);
		free (s->modules[i].path);
	}
	free (s->modules);
	for (i = 0; i < s->n_hooks; i++) {
		free (s->hooks[i].label);
		free (s->hooks[i].last);
		free (s->hooks[i].bt);
	}
	free (s->hooks);
	free (s->target);
	free (s);
}

void rn_cache_flush(RenefSession *s) {
	int i;
	rn_conn_lock (&s->conn);
	for (i = 0; i < RN_CACHE_PAGES; i++) {
		s->cache[i].used = false;
	}
	rn_conn_unlock (&s->conn);
}

RnStatus rn_exec(RenefSession *s, const char *lua, int timeout_ms, RnBuf *reply) {
	RnBuf cmd;
	bool ok;
	rn_buf_init (&cmd);
	ok = rn_buf_puts (&cmd, "exec ");
	/* renef_server takes everything before a "//" for the command name
	 * and the legacy protocol ends a command at a newline: code that
	 * contains either travels hex encoded instead */
	if (strstr (lua, "//") || strchr (lua, '\n')) {
		ok = ok && rn_lua_wrap_script (&cmd, lua, strlen (lua), "=r2renef");
	} else {
		ok = ok && rn_buf_puts (&cmd, lua);
	}
	if (!ok) {
		rn_buf_fini (&cmd);
		return RN_ERROR;
	}
	RnStatus st = rn_conn_request (&s->conn, cmd.data, cmd.len, RN_END_TAGGED, timeout_ms, reply);
	rn_buf_fini (&cmd);
	return st;
}

int rn_scan_reply(RenefSession *s, const RnBuf *reply, RnLineCb cb, void *user, RnBuf *other, bool *failed) {
	static const char lua_failed[] = "ERROR: Lua execution failed";
	/* Memory.patch() announces every patch on the output stream */
	static const char patched[] = "\xe2\x9c\x93 Patched";
	const char *p = reply->data;
	const char *end = p? p + reply->len: NULL;
	int tagged = 0;

	if (failed) {
		*failed = false;
	}
	while (p && p < end) {
		const char *nl = memchr (p, '\n', (size_t)(end - p));
		const char *le = nl? nl: end;
		size_t len = (size_t)(le - p);
		if (len > 0 && p[len - 1] == '\r') {
			len--;
		}
		if (len >= RN_TAG_LEN && !memcmp (p, RN_TAG, RN_TAG_LEN)) {
			tagged++;
			if (cb) {
				cb (user, p + RN_TAG_LEN, len - RN_TAG_LEN);
			}
		} else if (len == 2 && !memcmp (p, "OK", 2)) {
			/* exec status */
		} else if (len >= sizeof (lua_failed) - 1 && !memcmp (p, lua_failed, sizeof (lua_failed) - 1)) {
			if (failed) {
				*failed = true;
			}
		} else if (len >= sizeof (patched) - 1 && !memcmp (p, patched, sizeof (patched) - 1)) {
			/* noise */
		} else if (len > 9 && s->own_drop_notices > 0 && !memcmp (p, "[dropped ", 9)) {
			/* the agent's notice about a listing of ours that was too
			 * large for its queue (already fetched again in pages) */
			s->own_drop_notices--;
		} else if (len > 0) {
			if (other) {
				rn_buf_append (other, p, len);
				rn_buf_append (other, "\n", 1);
			} else {
				rn_conn_lock (&s->conn);
				rn_conn_stash_async (&s->conn, p, len);
				rn_conn_stash_async (&s->conn, "\n", 1);
				rn_conn_unlock (&s->conn);
			}
		}
		p = nl? nl + 1: end;
	}
	return tagged;
}

bool rn_r2_available(RenefSession *s) {
	return s && s->io && s->io->coreb.core && s->io->coreb.cmd;
}

void rn_r2cmd(RenefSession *s, const char *cmd) {
	if (rn_r2_available (s)) {
		s->io->coreb.cmd (s->io->coreb.core, cmd);
	}
}

void rn_r2cmdf(RenefSession *s, const char *fmt, ...) {
	va_list ap;
	if (!rn_r2_available (s)) {
		return;
	}
	va_start (ap, fmt);
	int n = vsnprintf (NULL, 0, fmt, ap);
	va_end (ap);
	if (n < 0) {
		return;
	}
	char *cmd = malloc ((size_t)n + 1);
	if (!cmd) {
		return;
	}
	va_start (ap, fmt);
	vsnprintf (cmd, (size_t)n + 1, fmt, ap);
	va_end (ap);
	s->io->coreb.cmd (s->io->coreb.core, cmd);
	free (cmd);
}

bool rn_r2num(RenefSession *s, const char *expr, ut64 *out) {
	if (!s || !s->io || !s->io->coreb.core || !s->io->coreb.numGet) {
		return false;
	}
	*out = s->io->coreb.numGet (s->io->coreb.core, expr);
	return true;
}

char *rn_flag_name(const char *name) {
	size_t i, n = strlen (name);
	char *o = malloc (n + 1);
	if (!o) {
		return NULL;
	}
	for (i = 0; i < n; i++) {
		char c = name[i];
		bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			|| (c >= '0' && c <= '9') || c == '_' || c == '.';
		o[i] = ok? c: '_';
	}
	o[n] = '\0';
	return o;
}
