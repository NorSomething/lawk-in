#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../include/common.h"

static int append_address(struct address_list *list, const char *address) {
    for (size_t i = 0; i < list->size; i++) {
        if (strcmp(list->addresses[i], address) == 0)
            return 0;
    }

    if (list->size == list->capacity) {
        size_t capacity = list->capacity ? list->capacity * 2 : 8;
        char **addresses = realloc(list->addresses, capacity * sizeof(*addresses));
        if (!addresses)
            return -1;
        list->addresses = addresses;
        list->capacity = capacity;
    }

    char *copy = strdup(address);
    if (!copy)
        return -1;
    list->addresses[list->size++] = copy;
    return 0;
}

void address_list_free(struct address_list *list) {
    if (!list)
        return;

    for (size_t i = 0; i < list->size; i++)
        free(list->addresses[i]);

    free(list->addresses);

    list->addresses = NULL;
    list->size = 0;
    list->capacity = 0;
}

int resolve_domain(const char *domain, struct address_list *ipv4_list, struct address_list *ipv6_list) {

    if (!domain || !ipv4_list || !ipv6_list)
        return -1;

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *results = NULL;

    int status = getaddrinfo(domain, NULL, &hints, &results);
    if (status != 0) {
        fprintf(stderr, "Could not resolve %s: %s\n", domain, gai_strerror(status));
        return -1;
    }

    int result = 0;
    for (const struct addrinfo *entry = results; entry; entry = entry->ai_next) {

        const void *address = NULL;
        struct address_list *list = NULL;
        char address_text[INET6_ADDRSTRLEN];

        if (entry->ai_family == AF_INET) {
            address = &((const struct sockaddr_in *)entry->ai_addr)->sin_addr;
            list = ipv4_list;
        }
        else if (entry->ai_family == AF_INET6) {
            address = &((const struct sockaddr_in6 *)entry->ai_addr)->sin6_addr;
            list = ipv6_list;
        }
        else {
            continue;
        }

        if (!inet_ntop(entry->ai_family, address, address_text, sizeof(address_text)) ||
            append_address(list, address_text) != 0) {
            fprintf(stderr, "Could not store resolved address for %s\n", domain);
            result = -1;
            break;
        }
    }

    freeaddrinfo(results);
    return result;
}
