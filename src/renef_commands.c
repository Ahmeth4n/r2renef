/* r2renef - MIT - Copyright 2025 */

#include "renef_commands.h"
#include "renef_socket.h"

volatile sig_atomic_t g_watch_interrupted = 0;

static void watch_sigint_handler(int sig) {
    g_watch_interrupted = 1;
}

char *handle_watch_cmd(RIODesc *desc) {
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

char *handle_load_cmd(RIODesc *desc, const char *cmd) {
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

    while (fgets(buf, sizeof(buf), file) != NULL) {
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
    snprintf(exec_cmd, sizeof(exec_cmd), "%s %s\n", RENEF_EXEC_COMMAND, result);

    free(result);
    return execute_renef_command(exec_cmd, desc->data);
}
