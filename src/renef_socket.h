/* r2renef - MIT - Copyright 2025 */

#ifndef RENEF_SOCKET_H
#define RENEF_SOCKET_H

#include "renef_types.h"

void drain_socket(void);
char *execute_renef_command(char *cmd, RenefUserData *rnf);

#endif
