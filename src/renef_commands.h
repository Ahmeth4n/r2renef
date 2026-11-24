/* r2renef - MIT - Copyright 2025-2026 */

#ifndef RENEF_COMMANDS_H
#define RENEF_COMMANDS_H

#include "renef_types.h"

/* Runs one `:` command. Returns malloc'd text for radare2 to print, or
 * NULL when there is nothing to print. */
char *rn_command(RenefSession *s, const char *cmd);

#endif
