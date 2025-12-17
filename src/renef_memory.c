/* r2renef - MIT - Copyright 2025 */

#include "renef_memory.h"
#include "renef_socket.h"

ut64 get_libc_base(RenefUserData *userdata) {
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

int parse_md_response(const char *response, ut8 *buf, int max_count) {
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

int renef_read(RIO *io, RIODesc *desc, ut8 *buf, int count) {
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

int renef_write(RIO *io, RIODesc *desc, const ut8 *buf, int count) {
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

ut64 renef_lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
    RenefUserData *userdata = desc->data;
    switch (whence) {
    case SEEK_SET: return offset;
    case SEEK_CUR: return io->off + offset;
    case SEEK_END: return userdata->size + offset;
    }
    return offset;
}
