#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>

int resolve_domain(const char *domain) {

    if (domain == NULL) {
        perror("Could not resolve domain...");
        return 1;
    }

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC; //for both ipv4 and ipv6

    struct addrinfo *results = NULL;

    int status = getaddrinfo(domain, NULL, &hints, &results);
    if (status != 0) {
        perror("Could not resolve status of domain..");
        return 1;
    }

    int result = 0;
    for (const struct addrinfo *entry = results; entry != NULL; entry = entry->ai_next) {

        const void *address = NULL;
        char address_text[INET6_ADDRSTRLEN];

        if (entry->ai_family == AF_INET) {
            const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)entry->ai_addr;
            address = &ipv4->sin_addr;
        }

        else if (entry->ai_family == AF_INET6) {
            const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)entry->ai_addr;
            address = &ipv6->sin6_addr;
        }

        else {
            continue;
        }

        if (inet_ntop(entry->ai_family, address, address_text, sizeof(address_text)) == NULL) {
            perror("inet_ntop");
            result = 1;
            continue;
        }

        printf("%s\n", address_text);
    }

    freeaddrinfo(results);
    return result;
}
