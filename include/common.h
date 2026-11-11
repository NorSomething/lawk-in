#ifndef common
#define common

#include <stddef.h>
#include <stdio.h>

struct domain_list {

    char domains[128][254];
    size_t size;

};

int load_blocklist(const char *path, struct domain_list *list);
int resolve_domain(const char *domain, char *ipv4_list, size_t ipv4_capacity, char *ipv6_list, size_t ipv6_capacity);
int firewall_init(void);
int firewall_add_ipv4(const char *address_list);
int firewall_add_ipv6(const char *address_list);

//helper
int read_len_of_files(FILE *fp);
int create_ruleset_string(const char *ip_list, char *output_buf, size_t max_len, int is_ipv6);

#endif
