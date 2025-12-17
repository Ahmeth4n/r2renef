#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(){
    char *md_response = ""\
        "0x78b5491060:  ff ff ff ff ff 44 0e 30 48 0c 1d 10 9e 02 9d 04  |.....D.0H.......|\n"
        "0x78b5491070:  0a 02 78 0c 1f 30 48 0e 00 de dd 44 0b 00 00 00  |..x..0H....D....|\n"
        "0x78b5491080:  30 00 00 00 5c 0e 00 00 bc b8 01 00 d4 00 00 00  |0...............|\n"
        "0x78b5491090:  08 6b 92 fc ff ff ff ff ff 44 0e 80 01 48 0c 1d  |.k.......D...H..|\n"
    "";

    char *copy = strdup(md_response);
    unsigned char buf[256];
    int buf_offset = 0;
    char *line_saveptr, *field_saveptr;
    char *line, *hex_part;

    for (line = strtok_r(copy, "\n", &line_saveptr);
        line != NULL;
        line = strtok_r(NULL, "\n", &line_saveptr)) {

        char *line_copy = strdup(line);

        strtok_r(line_copy, ":", &field_saveptr);
        hex_part = strtok_r(NULL, "|", &field_saveptr);

        if (hex_part) {
            char *p = hex_part;
            while (*p && buf_offset < sizeof(buf)) {

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

    free(copy);

    printf("Parsed %d bytes:\n", buf_offset);
    for (int i = 0; i < buf_offset; i++) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    return 0;
}
