/* r2renef - MIT - Copyright 2025-2026 */

#include <r_io.h>
#include <r_lib.h>

#include "renef_commands.h"
#include "renef_maps.h"
#include "renef_memory.h"
#include "renef_session.h"

RIOPlugin r_io_plugin_r2renef;

/* renef_server serves one client at a time: a second connection is
 * accepted by the kernel but never answered. Refuse it here instead of
 * letting it run into timeouts. */
#define RN_MAX_SESSIONS 8
static pthread_mutex_t g_sessions_lock = PTHREAD_MUTEX_INITIALIZER;
static RenefSession *g_sessions[RN_MAX_SESSIONS];

static bool session_busy(const char *host, const char *port) {
	bool busy = false;
	int i;
	pthread_mutex_lock (&g_sessions_lock);
	for (i = 0; i < RN_MAX_SESSIONS; i++) {
		RenefSession *o = g_sessions[i];
		if (o && rn_conn_is_open (&o->conn) && !strcmp (o->conn.host, host) && !strcmp (o->conn.port, port)) {
			busy = true;
		}
	}
	pthread_mutex_unlock (&g_sessions_lock);
	return busy;
}

static void session_register(RenefSession *s, bool add) {
	int i;
	pthread_mutex_lock (&g_sessions_lock);
	for (i = 0; i < RN_MAX_SESSIONS; i++) {
		if (add && !g_sessions[i]) {
			g_sessions[i] = s;
			break;
		}
		if (!add && g_sessions[i] == s) {
			g_sessions[i] = NULL;
		}
	}
	pthread_mutex_unlock (&g_sessions_lock);
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, SOCKETURI);
}

static bool __close(RIODesc *desc) {
	RenefSession *s = desc? desc->data: NULL;
	if (s) {
		session_register (s, false);
		rn_session_free (s);
		desc->data = NULL;
	}
	return true;
}

/* first line of a reply, without its newline */
static char *first_line(const RnBuf *b) {
	const char *d = b->data? b->data: "";
	const char *nl = strchr (d, '\n');
	return r_str_ndup (d, nl? (int)(nl - d): (int)strlen (d));
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	const char *err = NULL;
	RnUri uri;
	RnBuf reply;
	RIODesc *desc = NULL;

	if (!__check (io, pathname, false)) {
		return NULL;
	}
	const char *host = getenv ("RENEF_HOST");
	const char *port = getenv ("RENEF_PORT");
	if (!rn_parse_uri (pathname, R_STR_ISNOTEMPTY (host)? host: RN_DEFAULT_HOST,
			R_STR_ISNOTEMPTY (port)? port: RN_DEFAULT_PORT, &uri, &err)) {
		R_LOG_ERROR ("renef: %s", err);
		return NULL;
	}
	if (session_busy (uri.host, uri.port)) {
		R_LOG_ERROR ("renef: already connected to %s:%s; renef_server serves one client at a time", uri.host, uri.port);
		return NULL;
	}
	RenefSession *s = rn_session_new ();
	if (!s) {
		return NULL;
	}
	rn_buf_init (&reply);
	s->io = io;
	s->spawn = uri.spawn;
	s->target = strdup (uri.target);

	RnStatus st = rn_conn_connect (&s->conn, uri.host, uri.port);
	if (st != RN_OK) {
		R_LOG_ERROR ("renef: cannot connect to %s:%s (%s). Is renef_server running and the port forwarded?",
			uri.host, uri.port, st == RN_TIMEOUT? "timed out": "refused or unreachable");
		goto fail;
	}
	const char *fm = getenv ("RENEF_FRAMING");
	RnFramingMode mode_f = RN_FRAMING_AUTO;
	if (fm && (!strcmp (fm, "off") || !strcmp (fm, "0") || !strcmp (fm, "legacy"))) {
		mode_f = RN_FRAMING_OFF;
	} else if (fm && (!strcmp (fm, "on") || !strcmp (fm, "1"))) {
		mode_f = RN_FRAMING_ON;
	}
	st = rn_conn_probe (&s->conn, mode_f);
	if (st != RN_OK) {
		R_LOG_ERROR ("renef: %s:%s does not answer (%s)%s", uri.host, uri.port, rn_status_str (st),
			st == RN_TIMEOUT? ". Is another client connected? renef_server serves one at a time.": "");
		goto fail;
	}
	R_LOG_INFO ("renef: connected to %s:%s, %s protocol", uri.host, uri.port, s->conn.framed? "framed": "legacy");
	s->paged = s->conn.framed;

	/* spawn waits for the app to start and the agent to be injected */
	int tmo = rn_env_int ("RENEF_SPAWN_TIMEOUT", 60, 1, 3600) * 1000;
	char *cmd = r_str_newf ("%s %s", uri.spawn? "spawn": "attach", uri.target);
	st = cmd? rn_conn_request (&s->conn, cmd, strlen (cmd), RN_END_LINE, tmo, &reply): RN_ERROR;
	free (cmd);
	if (st != RN_OK) {
		R_LOG_ERROR ("renef: %s %s: %s", uri.spawn? "spawn": "attach", uri.target, rn_status_str (st));
		goto fail;
	}
	/* "OK <pid>" for spawn, "OK" for attach; anything else is the reason */
	const char *ok = reply.data;
	while (ok && strncmp (ok, "OK", 2)) {
		ok = strchr (ok, '\n');
		ok = ok? ok + 1: NULL;
	}
	if (!ok || (ok[2] != ' ' && ok[2] != '\n' && ok[2] != '\r' && ok[2] != '\0')) {
		char *line = first_line (&reply);
		R_LOG_ERROR ("renef: %s %s failed: %s", uri.spawn? "spawn": "attach", uri.target,
			R_STR_ISNOTEMPTY (line)? line: "empty reply");
		free (line);
		goto fail;
	}
	s->pid = uri.spawn? atoi (ok + 2): atoi (uri.target);
	R_LOG_INFO ("renef: %s %s, pid %d", uri.spawn? "spawned": "attached to", uri.target, s->pid);

	/* The full URI is the descriptor's name: radare2 reopens a file
	 * whose descriptor reports a different one. */
	desc = r_io_desc_new (io, &r_io_plugin_r2renef, pathname, R_PERM_RW | (rw & R_PERM_X), mode, s);
	if (!desc) {
		goto fail;
	}
	s->fd = desc->fd;
	session_register (s, true);
	rn_buf_fini (&reply);
	return desc;
fail:
	rn_buf_fini (&reply);
	rn_session_free (s);
	return NULL;
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
	RenefSession *s = desc? desc->data: NULL;
	if (!s) {
		return NULL;
	}
	s->io = io;
	if (R_STR_ISEMPTY (cmd)) {
		/* `=!` without a command: radare2 "initialises the io
		 * subsystem" this way once the descriptor is in place */
		rn_init_hook (s);
		return NULL;
	}
	return rn_command (s, cmd);
}

/* The three callbacks below are only consulted by radare2 for plugins
 * that set .isdbg, which this one deliberately does not: with it,
 * r_core_bin_load() takes the debugger path (r_debug_select() of the
 * target's pid in the HOST debugger, then r_bin_open() of the URI). They
 * are provided so that anything asking through the plugin gets the truth. */
static int __getpid(RIODesc *desc) {
	RenefSession *s = desc? desc->data: NULL;
	return s? s->pid: -1;
}

static bool __getbase(RIODesc *desc, ut64 *base) {
	RenefSession *s = desc? desc->data: NULL;
	if (!s || !base) {
		return false;
	}
	bool amb = false;
	const RnModule *m = rn_module_find (s, "libc.so", &amb);
	if (!m && s->n_modules) {
		m = &s->modules[0];
	}
	if (!m) {
		return false;
	}
	*base = m->base;
	return true;
}

RIOPlugin r_io_plugin_r2renef = {
	.meta = {
		.name = "r2renef",
		.desc = "Renef IO plugin for radare2 (renef://[host[:port]/]spawn/<pkg> or attach/<pid>)",
		.license = "MIT",
	},
	.uris = SOCKETURI,
	.open = __open,
	.close = __close,
	.seek = renef_lseek,
	.read = renef_read,
	.check = __check,
	.write = renef_write,
	.system = __system,
	.getpid = __getpid,
	.gettid = __getpid,
	.getbase = __getbase,
	.isdbg = false,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2renef,
	.version = R2_VERSION,
	.pkgname = "r2renef",
#ifdef R2_ABIVERSION
	/* radare2 >= 6.0 refuses a plugin built against another ABI instead
	 * of only comparing major.minor of the version string */
	.abiversion = R2_ABIVERSION,
#endif
};
#endif
