/* r2renef - MIT - Copyright 2025-2026 */

#ifndef RENEF_JAVA_H
#define RENEF_JAVA_H

#include "renef_types.h"

/* The Java side: classes, methods and hooks on Java methods. The work is
 * done in the target by src/renef_java.lua, which the first of these
 * commands loads there. Each returns malloc'd text for radare2 to print,
 * or NULL. */
char *rn_cmd_jc(RenefSession *s, const char *args);
char *rn_cmd_jm(RenefSession *s, const char *args);
char *rn_cmd_jhook(RenefSession *s, const char *args);
char *rn_cmd_jni(RenefSession *s, const char *args);
char *rn_cmd_jcode(RenefSession *s, const char *args);

#endif
