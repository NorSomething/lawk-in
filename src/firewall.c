#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nftables/libnftables.h>
#include <sys/ucontext.h>

#include "../include/common.h"

//helper - find # handle : handle_number
long long extract_handle(const char *output) {

    const char *loc = strstr(output, "# handle ");
    if (!loc)
        return -1;

    return atoll(loc+9);

}

//helper - make ruleset string
int create_ruleset_string(char *ip_list, char *output_buf, size_t max_len, int is_ipv6) {

    if (!ip_list || !output_buf)
        return -1;

    int written;

    // Initialize the command prefix
    if (is_ipv6 == 1) {
        written = snprintf(output_buf, max_len, "nft add element inet lawk-in ipv6_addr { ");
    }
    else {
        written = snprintf(output_buf, max_len, "nft add element inet lawk-in ipv4_addr { ");
    }

    if (written < 0 || (size_t)written >= max_len)
        return -1;

    // dups cuz strtok mods the string
    char *temp = strdup(ip_list);
    if (!temp)
        return -1;

    char *token = strtok(temp, ",");
    int first = 1;

    while (token != NULL) {
        //trip spaces
        while (*token == ' ')
            token++;

        //trim ending spaces
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\n' || *end == '\r')) {
            *end = '\0';
            end--;
        }

        if (*token != '\0') {
            char element_buf[256];
            if (!first) {
                snprintf(element_buf, sizeof(element_buf), ", %s", token);
            }
            else {
                snprintf(element_buf, sizeof(element_buf), "%s", token);
                first = 0;
            }

            //append to buffer
            if (strlen(output_buf) + strlen(element_buf) + 3 >= max_len) {
                free(temp);
                return -1; //buffer too small
            }
            strcat(output_buf, element_buf);
        }

        token = strtok(NULL, ",");
    }

    strcat(output_buf, " }");
    free(temp);
    return 0;
}


int firewall_init(char *ipv4_list, int ipv4_len, char *ipv6_list, int ipv6_len) {

    //create new context
    struct nft_ctx *ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx)
        return -1;

    unsigned int flags = nft_ctx_output_get_flags(ctx);
    flags = flags | NFT_CTX_OUTPUT_HANDLE | NFT_CTX_OUTPUT_ECHO;
    nft_ctx_output_set_flags(ctx, flags);

    //buffer nftable output
    nft_ctx_buffer_output(ctx);
    nft_ctx_buffer_error(ctx);

    //nftable boilerplate
    const char *setup_cmds =
        "add table inet lawk-in\n"
        "add chain inet lawk-in lawk-in_chain { type filter hook input priority 0; policy accept; }";

    if (nft_run_cmd_from_buffer(ctx, setup_cmds) != 0) {
        fprintf(stderr, "setup failed: %s", nft_ctx_get_error_buffer(ctx));
        nft_ctx_free(ctx);
        return -1;
    }

    //creating empty sets of ips
    const char *create_set =
        "add set inet lawk-in blocked_v4 { type ipv4_addr; }'\n"
        "add set inet lawk-in blocked_v6 '{ type ipv6_addr; }'";

    if (nft_run_cmd_from_buffer(ctx, create_set) != 0) {
       fprintf(stderr, "creating ip sets failed: %s\n", nft_ctx_get_error_buffer(ctx));
    }

    //create rule in oru new table
    // //for now it drops port 80 of http
//     const char *create_rule = "add rule inet lawk-in lawk-in_chain dport 80 drop\n";
//     printf("creating rule: tcp port 80 : dropped\n");
//
//     if (nft_run_cmd_from_buffer(ctx, create_rule) != 0) {
//         fprintf(stderr, "creating of rule failed: %s\n", nft_ctx_get_error_buffer(ctx));
//         return -1;
//     }

    //create rules for ipv4 and ipv6
    const char create_rule_ipv4[1024];
    create_ruleset_string(ipv4_list, create_rule_ipv4, ipv4_len, 0);
    if (nft_run_cmd_from_buffer(ctx, create_rule_ipv4) != 0) {
        fprintf(stderr, "creating ipv4 ruleset failed: %s\n", nft_ctx_get_error_buffer(ctx));
        return -1;
    }

    const char create_rule_ipv6[1024];
    create_ruleset_string(ipv6_list, create_rule_ipv6, ipv6_len, 1);
    if (nft_run_cmd_from_buffer(ctx, create_rule_ipv6) != 0) {
        fprintf(stderr, "creating ipv6 ruleset failed: %s\n", nft_ctx_buffer_error(ctx));
        return -1;
    }

    //reading output
    const char *output = nft_ctx_get_output_buffer(ctx);
    long long handle = extract_handle(output);
    if (handle < 0) {
        fprintf(stderr, "failed to capture rule handle from nft output..\n");
        nft_ctx_free(ctx);
        return -1;
    }

    printf("lawk-in rule created in kernel with handle %lld\n", handle);


    //clear context buffers
    nft_ctx_unbuffer_output(ctx);
    nft_ctx_unbuffer_error(ctx);
    nft_ctx_buffer_output(ctx);
    nft_ctx_buffer_error(ctx);


}
