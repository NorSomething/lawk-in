#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>

#include "../include/common.h"

int read_len_of_files(FILE *fp) {

    int lines = 0;
    int ch;
    int last_ch = '\n';

    while ((ch = fgetc(fp)) != EOF) {
        if (ch == '\n') {
            lines++;
        }
        last_ch = ch;
    }

    if (last_ch != '\n' && last_ch != EOF) {
            lines++;
    }

    return lines;

}

int load_blocklist(const char *path, struct domain_list *list) {

    FILE *config_file_ptr;

    config_file_ptr = fopen(path, "r");
    if (config_file_ptr == NULL) {
       perror("Something went wrong when opening the config file...");
       return 1;
    }

    list->size = 0;

    char *line = NULL;
    size_t line_capacity = 0;
    ssize_t line_length;

    while ((line_length = getline(&line, &line_capacity, config_file_ptr)) != -1) {

        //removing esc seq chars
        while (line_length > 0 && (line[line_length - 1] == '\n' || line[line_length - 1] == '\r')) {
            line[--line_length] = '\0';
        }

        size_t first = 0;
        while (first < (size_t)line_length && isspace((unsigned char)line[first])) {
            first++;
        }

        if (first == (size_t)line_length || line[first] == '#') {
            continue;
        }

        size_t last = (size_t)line_length;
        while (last > first && isspace((unsigned char)line[last - 1])) {
            last--;
        }

        line_length = (ssize_t)(last - first);
        memmove(line, line + first, (size_t)line_length);
        line[line_length] = '\0';

        if (list->size == 128) {
            fprintf(stderr, "Blocklist has more than 128 domains\n");
            free(line);
            fclose(config_file_ptr);
            exit(1);
        }

        if (line_length > 253) {
            fprintf(stderr, "Domain name exceeds 253 characters\n");
            free(line);
            fclose(config_file_ptr);
            exit(1);
        }

        //copy into next slot
        memcpy(list->domains[list->size], line, (size_t)line_length + 1);
        list->size++;
    }

    free(line);
    fclose(config_file_ptr);

}



int main() {

    struct domain_list list;
    load_blocklist("config/blocklist.conf", &list);

    for (size_t i = 0; i < list.size; i++) {
        printf("%s\n", list.domains[i]);
    }


  return 0;

}
