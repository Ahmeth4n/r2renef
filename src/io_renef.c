/* r2renef - MIT - Copyright 2025 */

#include "renef_types.h"
#include "renef_socket.h"
#include "renef_commands.h"
#include "renef_memory.h"

RIOPlugin r_io_plugin_r2renef;

static char *__system(RIO *io, RIODesc *desc, const char *cmd);
static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode);
static bool __check(RIO *io, const char *pathname, bool many);
static bool __close(RIODesc *desc);

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
    return r_str_startswith(pathname, SOCKETURI);
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
    if (!__check(io, pathname, 0)) {
        return NULL;
    }

    pathname += strlen(SOCKETURI);
    RenefUserData *userdata = R_NEW0(RenefUserData);
    if (!userdata) {
        return NULL;
    }

    R_MODES r_mode;

    userdata->sb = r_strbuf_new("");

    if (!g_socket) {
        g_socket = r_socket_new(false);
        if (!g_socket) {
            R_LOG_ERROR("Failed to create socket");
            R_FREE(userdata);
            return NULL;
        }

        if (!r_socket_connect(g_socket, "127.0.0.1", "1907", R_SOCKET_PROTO_TCP, 0)) {
            R_LOG_ERROR("Failed to connect to Renef");
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

        if (libc_base == (ut64)-1) {
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

    return r_io_desc_new(io,
            &r_io_plugin_r2renef,
            pathname,
            R_PERM_RW | (rw & R_PERM_X),
            mode,
            userdata);
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
    if (R_STR_ISEMPTY(cmd)) {
        return NULL;
    }

    if (!desc || !desc->data) {
        return NULL;
    }

    if (!g_socket) {
        return NULL;
    }

    RenefUserData *rnf = desc->data;

    if (!rnf->sb) {
        return NULL;
    }

    if (strncmp(cmd, RENEF_LOAD_COMMAND " ", strlen(RENEF_LOAD_COMMAND) + 1) == 0) {
        return handle_load_cmd(desc, cmd);
    }

    if (strcmp(cmd, RENEF_WATCH_COMMAND) == 0) {
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
    .seek = renef_lseek,
    .read = renef_read,
    .check = __check,
    .write = renef_write,
    .system = __system,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_IO,
    .data = &r_io_plugin_r2renef,
    .version = R2_VERSION
};
#endif
