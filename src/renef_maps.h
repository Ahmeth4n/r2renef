/* r2renef - MIT - Copyright 2025-2026 */

#ifndef RENEF_MAPS_H
#define RENEF_MAPS_H

#include "renef_types.h"

/* Re-reads the target's memory map (ranges and the modules derived from
 * them). On failure returns false with a message in `err` (may be NULL). */
bool rn_ranges_refresh(RenefSession *s, RnBuf *err);
/* fetches the map if there is none yet */
bool rn_ranges_ensure(RenefSession *s, RnBuf *err);

const RnRange *rn_range_at(RenefSession *s, ut64 addr);
const RnModule *rn_module_at(RenefSession *s, ut64 addr);
/* exact basename or path first, then a unique substring; *ambiguous is
 * set when several modules match */
const RnModule *rn_module_find(RenefSession *s, const char *name, bool *ambiguous);
/* The name to hand to hook()/Module.*: the full path when it fits the
 * agent's 127 byte buffer (it matches by substring), else the basename. */
const char *rn_module_luaname(const RnModule *m);
/* malloc'd "libc.so+0x1234", or "0x..." when addr is in no module */
char *rn_addr_label(RenefSession *s, ut64 addr);

/* Called when radare2 initialises the descriptor (`=!` with no command):
 * arch setup, map/flag sync, initial seek. */
void rn_init_hook(RenefSession *s);

char *rn_cmd_dm(RenefSession *s, const char *args, bool star);
char *rn_cmd_modules(RenefSession *s, const char *args, bool star);
char *rn_cmd_symbols(RenefSession *s, const char *args, bool star, bool symtab);
char *rn_cmd_sync(RenefSession *s, const char *args);
char *rn_cmd_diff(RenefSession *s, const char *args);

#endif
