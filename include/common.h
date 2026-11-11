#ifndef common
#define common

#include <stddef.h>
#include <stdio.h>

struct domain_list {

    char domains[128][254];
    size_t size;

};

struct address_list {

    char **addresses;
    size_t size;
    size_t capacity;

};

int load_blocklist(const char *path, struct domain_list *list);
void address_list_free(struct address_list *list);
int resolve_domain(const char *domain, struct address_list *ipv4_list, struct address_list *ipv6_list);
int firewall_init(void);
int firewall_add_ipv4(const struct address_list *address_list);
int firewall_add_ipv6(const struct address_list *address_list);

//helper
int read_len_of_files(FILE *fp);
int create_ruleset_string(const struct address_list *ip_list, char *output_buf, size_t max_len, int is_ipv6);

#endif
