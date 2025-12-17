/* r2renef - MIT - Copyright 2025 */

#ifndef RENEF_TYPES_H
#define RENEF_TYPES_H

#include <r_io.h>
#include <r_socket.h>

#define SOCKETURI "renef://"

#define RENEF_SPAWN_COMMAND "spawn"
#define RENEF_ATTACH_COMMAND "attach"
#define RENEF_LIST_APPS_COMMAND "la"
#define RENEF_EXEC_COMMAND "exec"
#define RENEF_MEMORY_DUMP_COMMAND "md"
#define RENEF_LOAD_COMMAND "l"
#define RENEF_WATCH_COMMAND "watch"

#define CACHE_SIZE 4096

typedef enum {
    SPAWN,
    ATTACH
} R_MODES;

typedef struct {
    R_MODES mode;
    RSocket *socket;
    RStrBuf *sb;
    int pid;
    size_t size;
    ut8 cache[CACHE_SIZE];
    ut64 cache_addr;
    int cache_len;
} RenefUserData;

extern RSocket *g_socket;
extern volatile sig_atomic_t g_watch_interrupted;

#endif
