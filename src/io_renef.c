/* r2renef - MIT - Copyright 2025 */

#include <r_io.h>
#include <r_socket.h>


RIOPlugin r_io_plugin_r2renef;
static RSocket *g_socket = NULL;
static volatile sig_atomic_t g_watch_interrupted = 0;


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

static void watch_sigint_handler(int sig) {
    g_watch_interrupted = 1;
}

static void drain_socket(void);
static char* handle_watch_cmd(RIODesc *desc);
static char* handle_load_cmd(RIODesc *desc, const char *cmd);
static ut64 get_libc_base(RenefUserData *userdata);
static char *execute_renef_command(char *cmd, RenefUserData *rnf); //after spawn - attach

static char *__system(RIO *io, RIODesc *desc, const char *cmd);
static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode);
static bool __check(RIO *io, const char *pathname, bool many);
static bool __close(RIODesc *desc);
static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count);
static ut64 __lseek(RIO *io, RIODesc *desc, ut64 offset, int whence);
static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count);

static char* handle_watch_cmd(RIODesc *desc) {
    g_watch_interrupted = 0;

    drain_socket();

    const char *watch_cmd = RENEF_WATCH_COMMAND "\n";
    int sent = r_socket_write(g_socket, (ut8*)watch_cmd, strlen(watch_cmd));
    R_LOG_WARN("Sending watch command, sent %d bytes", sent);

    struct sigaction sa, old_sa;
    sa.sa_handler = watch_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, &old_sa);

    printf("Watching... (Ctrl+C to stop)\n");
    fflush(stdout);

    char buf[4096];
    while (!g_watch_interrupted) {
        r_socket_block_time(g_socket, true, 0, 100);
        int n = r_socket_read(g_socket, (ut8*)buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            printf("%s", buf);
            fflush(stdout);
        }
    }

    sigaction(SIGINT, &old_sa, NULL);

    printf("\nWatch stopped.\n");
    return strdup("");
}



static char* handle_load_cmd(RIODesc *desc, const char *cmd){
    char *space = strchr(cmd, ' ');
    if (!space) {
        return NULL;
    }

    const char *path = space + 1;
    FILE *file = fopen(path, "r");
    
    if (file == NULL) {
        printf("Failed to open script file: %s\n", path);
        return NULL;
    }

    size_t capacity = 1024;
    size_t length = 0;
    char *result = malloc(capacity);
    result[0] = '\0'; 

    char buf[1024];

    while(fgets(buf, sizeof(buf), file) != NULL) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
            len--;
        }

        size_t needed = length + len + 3;

        if (needed > capacity) {
            capacity = needed * 2;
            char *tmp = realloc(result, capacity);

            if (!tmp) {
                free(result);
                fclose(file);
                return NULL;
            }
            result = tmp;
        }

        if (length > 0) {
            result[length++] = ' ';
        }

        memcpy(result + length, buf, len);
        length += len;
        result[length] = '\0';

    }

    fclose(file);

    char exec_cmd[strlen(result) + strlen(RENEF_EXEC_COMMAND) + 3];
    snprintf(exec_cmd,sizeof(exec_cmd), "%s %s\n", RENEF_EXEC_COMMAND, result);

    free(result);
    return execute_renef_command(exec_cmd, desc->data);
}

static void drain_socket(void) {
    char drain_buf[1024];
    int drained_total = 0;

    while (true) {
        r_socket_block_time(g_socket, true, 0, 100);  // 100ms timeout
        int n = r_socket_read(g_socket, (ut8*)drain_buf, sizeof(drain_buf));
        if (n <= 0) break;
        drained_total += n;
    }

}

static char *execute_renef_command(char *cmd, RenefUserData *rnf) {
    size_t cmd_len = strlen(cmd);
    char *cmd_nl = malloc(cmd_len + 2);

    if (!cmd_nl) {
        return NULL;
    }

    memcpy(cmd_nl, cmd, cmd_len);
    cmd_nl[cmd_len] = '\n';
    cmd_nl[cmd_len + 1] = '\0';

    drain_socket();

    int s_send = r_socket_write(g_socket, (ut8*)cmd_nl, strlen(cmd_nl));

    if (s_send < 0) {
        R_LOG_ERROR("Failed to send command");
        R_FREE(cmd_nl);
        return NULL;
    }

    char buf[1024];

    r_socket_block_time(g_socket, true, 2, 0); 
    int sp_response = r_socket_read(g_socket, (ut8*)buf, sizeof(buf) - 1);
    if (sp_response > 0) {
        buf[sp_response] = '\0';
        r_strbuf_append(rnf->sb, buf);
    }

    while (true) {
        r_socket_block_time(g_socket, true, 0, 400);  // 400ms timeout
        int sp_response = r_socket_read(g_socket, (ut8*)buf, sizeof(buf) - 1);

        if (sp_response <= 0)
            break;

        buf[sp_response] = '\0';
        r_strbuf_append(rnf->sb, buf);
    }

    const char *content = r_strbuf_get(rnf->sb);
    char *response = content ? strdup(content) : NULL;
    r_strbuf_set(rnf->sb, "");
    R_FREE(cmd_nl);
    return response;
}


static ut64 get_libc_base(RenefUserData *userdata) {
    ut64 libc_base = 0;

    char response[64];
    char exec_cmd[256];
    snprintf(exec_cmd, sizeof(exec_cmd), "%s print(string.format('0x%%x', Module.find('libc.so')))\n", RENEF_EXEC_COMMAND);
    r_socket_write(g_socket, (ut8*)exec_cmd, strlen(exec_cmd));

    r_socket_block_time(g_socket, true, 30, 0);
    int libc_response = r_socket_read(g_socket, (ut8*)response, sizeof(response) - 1);
    if (libc_response < 0) {
        return -1;
    }
    response[libc_response] = '\0';

    if (strncmp(response, "0x", 2) == 0) {
        libc_base = strtoull(response, NULL, 16);
        R_LOG_INFO("libc base address: 0x%"PFMT64x, libc_base);
    } else {
        R_LOG_ERROR("Invalid response: %s", response);
        return -1;
    }

    char drain[4096];
    r_socket_block_time(g_socket, false, 0, 0);
    while (r_socket_read(g_socket, (ut8*)drain, sizeof(drain)) > 0);
    r_socket_block_time(g_socket, true, 0, 0);

    return libc_base;
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
    RenefUserData *userdata = desc->data;
    ut64 addr = io->off;

    char *hex = malloc(count * 4 + 1);
    for (int i = 0; i < count; i++) {
        sprintf(hex + i * 4, "\\x%02x", buf[i]);
    }
    hex[count * 4] = '\0';

    char *cmd = malloc(64 + count * 4);
    sprintf(cmd, "exec Memory.patch(0x%"PFMT64x", \"%s\")", addr, hex);

    char *response = execute_renef_command(cmd, userdata);

    userdata->cache_len = 0;

    free(hex);
    free(cmd);
    free(response);

    return count;
}

static ut64 __lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
    RenefUserData *userdata = desc->data;
    switch (whence) {
    case SEEK_SET: return offset;
    case SEEK_CUR: return io->off + offset;
    case SEEK_END: return userdata->size + offset;
    }
    return offset;
}

static int parse_md_response(const char *response, ut8 *buf, int max_count) {
    int buf_offset = 0;
    char *resp_copy = strdup(response);
    char *line_saveptr, *field_saveptr;
    char *line, *hex_part;

    for (line = strtok_r(resp_copy, "\n", &line_saveptr);
        line != NULL;
        line = strtok_r(NULL, "\n", &line_saveptr)) {

        if (strncmp(line, "Memory", 6) == 0) continue;
        if (strncmp(line, "ERROR", 5) == 0) continue;

        char *line_copy = strdup(line);

        strtok_r(line_copy, ":", &field_saveptr);
        hex_part = strtok_r(NULL, "|", &field_saveptr);

        if (hex_part) {
            char *p = hex_part;
            while (*p && buf_offset < max_count) {
                while (*p == ' ') p++;
                if (!*p) break;

                unsigned int byte;
                if (sscanf(p, "%2x", &byte) == 1) {
                    buf[buf_offset++] = (unsigned char)byte;
                    p += 2;
                } else {
                    break;
                }
            }
        }
        free(line_copy);
    }

    free(resp_copy);
    return buf_offset;
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
    ut64 addr = io->off;
    RenefUserData *userdata = desc->data;

    if (userdata->cache_len > 0 &&
        addr >= userdata->cache_addr &&
        addr + count <= userdata->cache_addr + userdata->cache_len) {

        int offset = addr - userdata->cache_addr;
        memcpy(buf, userdata->cache + offset, count);
        return count;
    }

    int fetch_size = (count > CACHE_SIZE) ? count : CACHE_SIZE;

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "%s 0x%"PFMT64x" %d",
             RENEF_MEMORY_DUMP_COMMAND, addr, fetch_size);

    char *response = execute_renef_command(cmd, userdata);

    if (response == NULL) {
        R_LOG_ERROR("No response for addr=0x%"PFMT64x, addr);
        return 0;
    }

    userdata->cache_len = parse_md_response(response, userdata->cache, CACHE_SIZE);
    userdata->cache_addr = addr;

    free(response);

    if (userdata->cache_len <= 0) {
        return 0;
    }

    int to_copy = (count <= userdata->cache_len) ? count : userdata->cache_len;
    memcpy(buf, userdata->cache, to_copy);

    if (to_copy >= 4) {
        R_LOG_WARN("Read %d bytes for 0x%"PFMT64x" (cached %d): %02x %02x %02x %02x...",
            to_copy, addr, userdata->cache_len, buf[0], buf[1], buf[2], buf[3]);
    }

    return to_copy;
}

static bool __close(RIODesc *desc) {
    RenefUserData *userdata = desc->data;
    if (userdata) {
        if (userdata->socket && userdata->socket == g_socket) {
            r_socket_close(g_socket);
            r_socket_free(g_socket);
            g_socket = NULL;
        }
        if (userdata->sb) {
            r_strbuf_free(userdata->sb);
        }
        R_FREE(desc->data);
    }
    return true;
}

static bool __check(RIO *io, const char *pathname, bool many) {
    return r_str_startswith (pathname, SOCKETURI);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
    if (!__check (io, pathname, 0)) {
        return NULL;
    }

    pathname += strlen (SOCKETURI);
    RenefUserData *userdata = R_NEW0 (RenefUserData);
    if (!userdata) {
        return NULL;
    }

    R_MODES r_mode;

	userdata->sb = r_strbuf_new ("");

    if (!g_socket) {
        g_socket = r_socket_new(false);
        if (!g_socket) {
            R_LOG_ERROR ("Failed to create socket");
            R_FREE(userdata);
            return NULL;
        }

        if (!r_socket_connect(g_socket, "127.0.0.1", "1907", R_SOCKET_PROTO_TCP, 0)) {
            R_LOG_ERROR ("Failed to connect to Renef");
            r_socket_free(g_socket);
            g_socket = NULL;
            R_FREE(userdata);
            return NULL;
        }

        R_LOG_INFO("Renef injection waiting... sock_fd: %d", g_socket->fd);

        char *path_copy = strdup(pathname);
        char *command_name = strtok(path_copy, "/");
        char *inject_target = strtok(NULL, "/");

        if (!inject_target) {
            R_LOG_ERROR("Invalid URI format");
            free(path_copy);
            r_socket_close(g_socket);
            r_socket_free(g_socket);
            g_socket = NULL;
            R_FREE(userdata);
            return NULL;
        }

        char *mode_str = strdup(command_name);
        r_mode = (strcmp(command_name, RENEF_SPAWN_COMMAND) == 0) ? SPAWN : ATTACH;

        size_t spawn_cmd_len = strlen(command_name) + strlen(inject_target) + 3;
        char *spawn_cmd = (char*)malloc(spawn_cmd_len);
        sprintf(spawn_cmd, "%s %s\n", command_name, inject_target);

        int p_send = r_socket_write(g_socket, (ut8*)spawn_cmd, strlen(spawn_cmd));

        R_FREE(spawn_cmd);
        R_FREE(path_copy);

        if (p_send < 0) {
            R_LOG_ERROR("Failed to send spawn command");
            R_FREE(mode_str);
            r_socket_close(g_socket);
            r_socket_free(g_socket);
            g_socket = NULL;
            R_FREE(userdata);
            return NULL;
        }

        char response[64] = {0};
        r_socket_block_time(g_socket, true, 30, 0);
        int sp_response = r_socket_read(g_socket, (ut8*)response, sizeof(response) - 1);
        if (sp_response < 0) {
            R_LOG_ERROR("Failed to receive spawn response");
            R_FREE(mode_str);
            r_socket_close(g_socket);
            r_socket_free(g_socket);
            g_socket = NULL;
            R_FREE(userdata);
            return NULL;
        }

        
        

        if (strncmp(response, "OK", 2) == 0) {
            if (r_mode == SPAWN)
                userdata->pid = atoi(response + 3);
            else
                userdata->pid = atoi(inject_target);
        } else {
            R_LOG_ERROR("Invalid response: %s", response);
            R_FREE(mode_str);
            r_socket_close(g_socket);
            r_socket_free(g_socket);
            g_socket = NULL;
            R_FREE(userdata);
            return NULL;
        }

        R_LOG_INFO("Injection completed. Mode: %s PID: %d", mode_str, userdata->pid);

        ut64 libc_base = get_libc_base(userdata);
        
        if (libc_base == (ut64)-1){
            R_LOG_ERROR("Failed to receive spawn response");
            R_FREE(mode_str);
            r_socket_close(g_socket);
            r_socket_free(g_socket);
            g_socket = NULL;
            R_FREE(userdata);
            return NULL;
        }

        io->off = libc_base;
        userdata->size = UT64_MAX;
        R_FREE(mode_str);
    }

    userdata->socket = g_socket;
    userdata->mode = r_mode;

    return r_io_desc_new (io,
            &r_io_plugin_r2renef,
            pathname,
            R_PERM_RW | (rw & R_PERM_X),
            mode,
            userdata);
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {

    if(R_STR_ISEMPTY(cmd)) {
        return NULL;
    }

    if (!desc || !desc->data) {
        return NULL;
    }

    if (!g_socket) {
        return NULL;
    }

    //R_LOG_WARN ("system command executed '%s'", cmd);
	RenefUserData *rnf = desc->data;

    if (!rnf->sb) {
        return NULL;
    }

    if (strncmp(cmd, RENEF_LOAD_COMMAND " ", strlen(RENEF_LOAD_COMMAND) + 1) == 0) {
        /*
            We need to handle load command because it requires special processing.
            for renef CLI, all scripts reading from local filesystem.
            but r2renef plugin reading from mobile device for now.
            in this func, we're going to handle "l" command and convert to "exec <lua_code>" format here.
        */
        return handle_load_cmd(desc, cmd);
    }

    if (strcmp(cmd, RENEF_WATCH_COMMAND) == 0) {
        /* 
            We recommend using this when hook specific trigger functions 
            (if you need to get onEnter - onLeave callbacks)
        */
        return handle_watch_cmd(desc);
    }


    return execute_renef_command((char *)cmd, rnf);
}

RIOPlugin r_io_plugin_r2renef = {
    .meta = {
        .name = "r2renef",
        .desc = "Renef IO plugin for radare2",
        .license = "MIT",
    },
    .uris = SOCKETURI,
    .open = __open,
    .close = __close,
    .seek = __lseek,
    .read = __read,
    .check = __check,
    .write = __write,
    .system = __system,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_IO,
    .data = &r_io_plugin_r2renef,
    .version = R2_VERSION
};
#endif
