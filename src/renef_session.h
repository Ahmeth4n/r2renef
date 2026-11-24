/* r2renef - MIT - Copyright 2025-2026 */

#ifndef RENEF_SESSION_H
#define RENEF_SESSION_H

#include "renef_types.h"

/* Every line the plugin's own Lua snippets print starts with this, so a
 * reply can be told apart from anything else the target writes on the
 * same stream (hook callbacks, syscall traces). */
#define RN_TAG "@r2:"
#define RN_TAG_LEN 4

RenefSession *rn_session_new(void);
void rn_session_free(RenefSession *s);

long long rn_now_ms(void);

/* Runs Lua in the target ("exec <lua>"). The raw reply is appended to
 * `reply`. */
RnStatus rn_exec(RenefSession *s, const char *lua, int timeout_ms, RnBuf *reply);

/* Called for each tagged line of a reply, without the tag. */
typedef void (*RnLineCb)(void *user, const char *line, size_t len);

/* Walks a reply line by line: tagged lines go to `cb`, exec's own status
 * line is dropped, every other line is appended to `other` or, if that is
 * NULL, filed as unsolicited output. Returns the number of tagged lines;
 * *failed is set when the reply carries exec's failure status. */
int rn_scan_reply(RenefSession *s, const RnBuf *reply, RnLineCb cb, void *user, RnBuf *other, bool *failed);

/* radare2 side: run a command in the core that owns this descriptor. */
bool rn_r2_available(RenefSession *s);
void rn_r2cmd(RenefSession *s, const char *cmd);
void rn_r2cmdf(RenefSession *s, const char *fmt, ...) __attribute__ ((format (printf, 2, 3)));
/* evaluates a radare2 expression ($$, flags, math); false if unavailable */
bool rn_r2num(RenefSession *s, const char *expr, ut64 *out);

/* malloc'd copy of `name` restricted to characters valid in a flag name */
char *rn_flag_name(const char *name);

/* forgets every cached page (the target's memory may have changed) */
void rn_cache_flush(RenefSession *s);

#endif
