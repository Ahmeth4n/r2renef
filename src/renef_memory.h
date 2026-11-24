/* r2renef - MIT - Copyright 2025-2026 */

#ifndef RENEF_MEMORY_H
#define RENEF_MEMORY_H

#include "renef_types.h"

int renef_read(RIO *io, RIODesc *desc, ut8 *buf, int count);
int renef_write(RIO *io, RIODesc *desc, const ut8 *buf, int count);
ut64 renef_lseek(RIO *io, RIODesc *desc, ut64 offset, int whence);

/* "lua" or "md": the path the next read will take */
const char *rn_read_path_name(RenefSession *s);

#endif
