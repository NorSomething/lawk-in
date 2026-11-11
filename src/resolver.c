#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "../include/common.h"

static int append_address(char *list, size_t capacity, const char *address) {
    size_t address_len = strlen(address);
    size_t used = strlen(list);

    const char *entry = list;
    while (*entry) {
        const char *end = strchr(entry, ',');
        size_t entry_len;

        if (end) {
            entry_len = (size_t)(end - entry);
        }

        else {
            entry_len = strlen(entry);
        }

        if (entry_len == address_len && memcmp(entry, address, address_len) == 0)
            return 0;

        if (!end)
            break;

        entry = end + 1;
    }

    size_t separator_len;
    if (used) {
        separator_len = 1;
    }
    else {
        separator_len = 0;
    }

    if (used + separator_len + address_len + 1 > capacity)
        return -1;
    if (separator_len)
        list[used++] = ',';
    memcpy(list + used, address, address_len + 1);
    return 0;
}

int resolve_domain(const char *domain, char *ipv4_list, size_t ipv4_capacity, char *ipv6_list, size_t ipv6_capacity) {

    if (!domain || !ipv4_list || !ipv6_list || !ipv4_capacity || !ipv6_capacity)
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
        char address_text[INET6_ADDRSTRLEN];
        char *list = NULL;
        size_t capacity = 0;

        if (entry->ai_family == AF_INET) {
            address = &((const struct sockaddr_in *)entry->ai_addr)->sin_addr;
            list = ipv4_list;
            capacity = ipv4_capacity;
        }

        else if (entry->ai_family == AF_INET6) {
            address = &((const struct sockaddr_in6 *)entry->ai_addr)->sin6_addr;
            list = ipv6_list;
            capacity = ipv6_capacity;
        }

        else {
            continue;
        }

        if (!inet_ntop(entry->ai_family, address, address_text, sizeof(address_text)) ||
            append_address(list, capacity, address_text) != 0) {
            fprintf(stderr, "Could not store resolved address for %s\n", domain);
            result = -1;
            break;
        }
    }

    freeaddrinfo(results);
    return result;
}
