#ifndef common
#define common

#include <stddef.h>
#include <stdio.h>

struct domain_list {

    char domains[128][254];
    size_t size;

};

int load_blocklist(const char *path, struct domain_list *list);
int resolve_domain(const char *domain);
int firewall_init(char *ipv4_list, int ipv4_len, char *ipv6_list, int ipv6_len);

//helper
int read_len_of_files(FILE *fp);
long long extract_handle(const char *output);
int create_ruleset_string(char *ip_list, char *output_buf, size_t max_len, int is_ipv6);

#endif
