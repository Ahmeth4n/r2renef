/* r2renef - MIT - Copyright 2025-2026 */

#ifndef RENEF_TYPES_H
#define RENEF_TYPES_H

#include <r_io.h>
#include "renef_socket.h"

#define SOCKETURI "renef://"

#define RN_PAGE_SIZE 4096
#define RN_PAGE_MASK (~(ut64)(RN_PAGE_SIZE - 1))
#define RN_CACHE_PAGES 64
/* bytes fetched by one Lua read: 2 hex chars per byte on one print() line,
 * which has to stay well below the agent's 256KB output queue */
#define RN_LUA_READ_MAX (8 * RN_PAGE_SIZE)
/* bytes patched by one request ("\xNN" per byte in a Lua literal): the
 * command has to fit the 64KB command buffer of public renef agents */
#define RN_WRITE_CHUNK 8192
/* hex characters of a script sent by one request, for the same reason */
#define RN_SCRIPT_CHUNK 40000

typedef enum {
	RN_READ_AUTO = 0, /* Lua path once it has proven itself, else md */
	RN_READ_LUA,
	RN_READ_MD
} RnReadPath;

typedef enum {
	RN_MAPS_RANGES = 0, /* one io map per mapped range of the target */
	RN_MAPS_FULL        /* leave radare2's single catch-all map alone */
} RnMapsMode;

typedef struct {
	bool used;
	ut64 base;
	int len;            /* readable bytes from base; 0 = unreadable page */
	long long stamp;
	ut8 data[RN_PAGE_SIZE];
} RnPage;

typedef struct {
	ut64 start;
	ut64 end;
	ut64 offset;
	char perms[5];
	char *path;
} RnRange;

typedef struct {
	char *name;         /* basename */
	char *path;
	ut64 base;          /* lowest mapping of the file */
	ut64 end;
	bool exec_only;     /* has an executable mapping without read permission */
	bool dup_name;      /* another module has the same basename */
} RnModule;

typedef struct {
	int id;             /* index in the agent's hook table, -1 if unknown */
	ut64 addr;
	bool got;           /* PLT/GOT hook (caller=...) instead of inline */
	bool foreign;       /* found in the agent's list, not set with :hook: kind unknown */
	char *label;        /* "libc.so+0x1234" */
	unsigned long hits;
	char *last;         /* last line the callback printed */
	ut64 *bt;           /* last backtrace captured by the callback */
	int bt_len;
	long long bt_stamp;
	bool dirty;         /* hit data changed since the comment was written */
} RnHook;

typedef struct {
	RenefConn conn;
	RIO *io;
	int fd;             /* radare2 descriptor number, -1 before it exists */
	bool spawn;
	int pid;
	char *target;
	ut64 off;           /* descriptor position: radare2 seeks, then reads */

	RnPage cache[RN_CACHE_PAGES];
	int cache_ttl_ms;
	RnReadPath read_path;
	bool lua_read_checked;   /* Lua path compared against md once */
	int events_cmd;          /* server has the `events` command: 0 = unknown, 1 = yes, -1 = no */
	bool lua_read_ok;
	int lua_read_strikes;
	unsigned long n_md_reads;
	unsigned long n_lua_reads;
	int memdump_cmd;         /* server has `memdump <pid> <range>`: 0 = unknown, 1 = yes, -1 = no */
	unsigned long n_proc_reads;

	RnMapsMode maps_mode;
	bool autosync;
	bool init_done;
	bool maps_applied;
	bool modlist_only;  /* map came from Module.list(): first mapping per library only */
	bool paged;         /* listings are fetched in pages (see renef_maps.c) */
	int own_drop_notices; /* "[dropped ...]" lines still to come that our own oversized listing caused */
	RnRange *ranges;
	size_t n_ranges;
	RnModule *modules;
	size_t n_modules;

	RnHook *hooks;
	size_t n_hooks;
	RnBuf async_tail;   /* incomplete last line of unsolicited output */
} RenefSession;

#endif
