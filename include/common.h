#ifndef common
#define common

#include <stddef.h>
#include <stdio.h>

struct domain_list {

    char domains[128][254];
    size_t size;

};

int load_blocklist(const char *path, struct domain_list *list);

//helper
int read_len_of_files(FILE *fp);

#endif
