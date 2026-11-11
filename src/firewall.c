#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nftables/libnftables.h>

#include "../include/common.h"

//this func is ai slop cuz im too lazy to do string work in C
int create_ruleset_string(const char *ip_list, char *output_buf, size_t max_len, int is_ipv6) {
    if (!ip_list || !output_buf || max_len == 0)
        return -1;

    const char *set_name = is_ipv6 ? "blocked_v6" : "blocked_v4";
    int written = snprintf(output_buf, max_len, "add element inet lawk-in %s { ", set_name);
    if (written < 0 || (size_t)written >= max_len)
        return -1;

    size_t used = (size_t)written;
    char *copy = strdup(ip_list);
    if (!copy)
        return -1;

    int first = 1;
    char *saveptr = NULL;
    for (char *token = strtok_r(copy, ",", &saveptr); token; token = strtok_r(NULL, ",", &saveptr)) {

        while (*token == ' ' || *token == '\t' || *token == '\n' || *token == '\r')
            token++;
        size_t token_len = strlen(token);

        while (token_len && (token[token_len - 1] == ' ' || token[token_len - 1] == '\t' || token[token_len - 1] == '\n' || token[token_len - 1] == '\r'))
            token[--token_len] = '\0';
        if (!token_len)
            continue;

        int separator_len = first ? 0 : 2;
        if (used + (size_t)separator_len + token_len + 3 > max_len) {
            free(copy);
            return -1;
        }

        if (!first) {
            output_buf[used++] = ',';
            output_buf[used++] = ' ';
        }

        memcpy(output_buf + used, token, token_len);
        used += token_len;
        first = 0;
    }
    free(copy);

    if (first || used + 3 > max_len)
        return -1;
    memcpy(output_buf + used, " }", 3);
    return 0;
}

static int run_nft_command(const char *command) {
    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
        return -1;

    int result = nft_run_cmd_from_buffer(ctx, command);
    if (result != 0)
        fprintf(stderr, "nft command failed: %s\n", nft_ctx_get_error_buffer(ctx));

    nft_ctx_free(ctx);

    if (result == 0)
        return 0;
    else
        return 1;
}

int firewall_init(void) {
    const char *setup_cmds =
        "add table inet lawk-in\n"
        "add chain inet lawk-in lawk-in_chain { type filter hook input priority 0; policy accept; }\n"
        "add chain inet lawk-in lawk-in_output { type filter hook output priority 0; policy accept; }\n"
        "add set inet lawk-in blocked_v4 { type ipv4_addr; }\n"
        "add set inet lawk-in blocked_v6 { type ipv6_addr; }\n"
        "add rule inet lawk-in lawk-in_chain ip saddr @blocked_v4 drop\n"
        "add rule inet lawk-in lawk-in_chain ip6 saddr @blocked_v6 drop\n"
        "add rule inet lawk-in lawk-in_output ip daddr @blocked_v4 drop\n"
        "add rule inet lawk-in lawk-in_output ip6 daddr @blocked_v6 drop";
    return run_nft_command(setup_cmds);
}

static int firewall_add_addresses(const char *address_list, int is_ipv6) {
    if (!address_list || !*address_list)
        return -1;

    size_t command_size = strlen(address_list) + 96;
    char *command = malloc(command_size);
    if (!command)
        return -1;

    int result = create_ruleset_string(address_list, command, command_size, is_ipv6);
    if (result == 0)
        result = run_nft_command(command);
    free(command);
    return result;
}

int firewall_add_ipv4(const char *address_list) {
    return firewall_add_addresses(address_list, 0);
}

int firewall_add_ipv6(const char *address_list) {
    return firewall_add_addresses(address_list, 1);
}
