#include "../inc/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int parse_mac(const char *str, uint8_t *mac) {
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    return 0;
}

static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    char ip_str[32];
    int prefix_len;

    if (sscanf(str, "%31[^/]/%d", ip_str, &prefix_len) != 2)
        return -1;

    if (prefix_len < 0 || prefix_len > 32)
        return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1)
        return -1;

    *ip = addr.s_addr;

    if (prefix_len == 0)
        *netmask = 0;
    else
        *netmask = htonl(0xFFFFFFFF << (32 - prefix_len));

    if (network)
        *network = *ip & *netmask;

    return 0;
}

static int parse_hex_bytes(const char *str, uint8_t *out, int expected_len) {
    int len = strlen(str);
    if (len != expected_len * 2)
        return -1;

    for (int i = 0; i < expected_len; i++) {
        unsigned int val;
        if (sscanf(str + i * 2, "%2x", &val) != 1)
            return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}


int config_validate(struct app_config *cfg) {
    if (cfg->global_frame_size == 0) {
        fprintf(stderr, "[GLOBAL] frame_size not specified\n");
        return -1;
    }

    if (cfg->global_batch_size == 0) {
        fprintf(stderr, "[GLOBAL] batch_size not specified\n");
        return -1;
    }

    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];

        if (local->ifname[0] == '\0') {
            fprintf(stderr, "LOCAL[%d]: interface not specified\n", i);
            return -1;
        }
        if (local->umem_mb == 0) {
            fprintf(stderr, "LOCAL %s: umem_mb not specified\n", local->ifname);
            return -1;
        }
        if (local->ring_size == 0) {
            fprintf(stderr, "LOCAL %s: ring_size not specified\n", local->ifname);
            return -1;
        }

        uint32_t min_umem_mb = (local->ring_size * 2 * local->frame_size) / (1024 * 1024);
        if (local->umem_mb < min_umem_mb) {
            fprintf(stderr, "LOCAL %s: umem_mb=%d too small for ring_size=%d (min: %d)\n",
                    local->ifname, local->umem_mb, local->ring_size, min_umem_mb);
            return -1;
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *wan = &cfg->wans[i];

        if (wan->ifname[0] == '\0') {
            fprintf(stderr, "WAN[%d]: interface not specified\n", i);
            return -1;
        }

        if (wan->umem_mb == 0) {
            fprintf(stderr, "WAN %s: umem_mb not specified\n", wan->ifname);
            return -1;
        }

        if (wan->ring_size == 0) {
            fprintf(stderr, "WAN %s: ring_size not specified\n", wan->ifname);
            return -1;
        }

        if (wan->window_size == 0) {
            fprintf(stderr, "WAN %s: window_kb not specified\n", wan->ifname);
            return -1;
        }

        uint32_t min_umem_mb = (wan->ring_size * 2 * wan->frame_size) / (1024 * 1024);
        if (wan->umem_mb < min_umem_mb) {
            fprintf(stderr, "WAN %s: umem_mb=%d too small for ring_size=%d (min: %d)\n",
                    wan->ifname, wan->umem_mb, wan->ring_size, min_umem_mb);
            return -1;
        }
    }

    return 0;
}

int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip) {
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];
        if ((dest_ip & local->netmask) == local->network) {
            return i;
        }
    }
    return -1;
}

int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    return parse_ip_cidr(str, ip, netmask, network);
}

int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len) {
    return parse_hex_bytes(str, out, expected_len);
}
