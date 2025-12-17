/* r2renef - MIT - Copyright 2025 */

#ifndef RENEF_COMMANDS_H
#define RENEF_COMMANDS_H

#include "renef_types.h"

char *handle_watch_cmd(RIODesc *desc);
char *handle_load_cmd(RIODesc *desc, const char *cmd);

#endif
