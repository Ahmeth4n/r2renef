/* r2renef - MIT - Copyright 2025 */

#ifndef RENEF_MEMORY_H
#define RENEF_MEMORY_H

#include "renef_types.h"

ut64 get_libc_base(RenefUserData *userdata);
int parse_md_response(const char *response, ut8 *buf, int max_count);
int renef_read(RIO *io, RIODesc *desc, ut8 *buf, int count);
int renef_write(RIO *io, RIODesc *desc, const ut8 *buf, int count);
ut64 renef_lseek(RIO *io, RIODesc *desc, ut64 offset, int whence);

#endif
