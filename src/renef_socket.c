/* r2renef - MIT - Copyright 2025 */

#include "renef_socket.h"

RSocket *g_socket = NULL;

void drain_socket(void) {
    char drain_buf[1024];
    int drained_total = 0;

    while (true) {
        r_socket_block_time(g_socket, true, 0, 100);
        int n = r_socket_read(g_socket, (ut8*)drain_buf, sizeof(drain_buf));
        if (n <= 0) break;
        drained_total += n;
    }
}

char *execute_renef_command(char *cmd, RenefUserData *rnf) {
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
        r_socket_block_time(g_socket, true, 0, 400);
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
