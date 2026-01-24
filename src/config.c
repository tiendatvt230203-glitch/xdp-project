#include "../inc/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

// Parse MAC string "xx:xx:xx:xx:xx:xx" to bytes
int parse_mac(const char *str, uint8_t *mac)
{
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

// Parse IP/CIDR string "192.168.9.1/24" to ip and netmask
static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network)
{
    char ip_str[32];
    int prefix_len;

    // Parse "IP/prefix"
    if (sscanf(str, "%31[^/]/%d", ip_str, &prefix_len) != 2) {
        return -1;
    }

    if (prefix_len < 0 || prefix_len > 32) {
        return -1;
    }

    // Convert IP string to network byte order
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }
    *ip = addr.s_addr;  // Already in network byte order

    // Calculate netmask from prefix length
    if (prefix_len == 0) {
        *netmask = 0;
    } else {
        *netmask = htonl(0xFFFFFFFF << (32 - prefix_len));
    }

    // Calculate network address
    *network = *ip & *netmask;

    return 0;
}

// Trim whitespace from string
static char *trim(char *str)
{
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

int config_load(struct app_config *cfg, const char *filename)
{
    FILE *fp;
    char line[512];
    char type[32], ifname[IF_NAMESIZE], mac_str[32], ip_cidr[64];

    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->bpf_file, "bpf/xdp_redirect.o", sizeof(cfg->bpf_file) - 1);

    fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen config");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim(line);

        // Skip comments and empty lines
        if (trimmed[0] == '#' || trimmed[0] == '\0')
            continue;

        // Parse GATEWAY_MAC
        if (strncmp(trimmed, "GATEWAY_MAC", 11) == 0) {
            if (sscanf(trimmed, "GATEWAY_MAC %31s", mac_str) == 1) {
                parse_mac(mac_str, cfg->gateway_mac);
            }
            continue;
        }

        // Parse BPF_FILE
        if (strncmp(trimmed, "BPF_FILE", 8) == 0) {
            sscanf(trimmed, "BPF_FILE %255s", cfg->bpf_file);
            continue;
        }

        // Parse interface entries: TYPE INTERFACE MAC IP/CIDR
        if (sscanf(trimmed, "%31s %15s %31s %63s", type, ifname, mac_str, ip_cidr) == 4) {
            if (strcmp(type, "LOCAL") == 0 && cfg->local_count < MAX_INTERFACES) {
                struct iface_config *iface = &cfg->locals[cfg->local_count];
                iface->type = IFACE_TYPE_LOCAL;
                strncpy(iface->ifname, ifname, IF_NAMESIZE - 1);
                parse_mac(mac_str, iface->mac);
                if (parse_ip_cidr(ip_cidr, &iface->ip, &iface->netmask, &iface->network) != 0) {
                    fprintf(stderr, "Invalid IP/CIDR for LOCAL %s: %s\n", ifname, ip_cidr);
                    fclose(fp);
                    return -1;
                }
                iface->enabled = 1;
                cfg->local_count++;
            }
            else if (strcmp(type, "WAN") == 0 && cfg->wan_count < MAX_INTERFACES) {
                struct iface_config *iface = &cfg->wans[cfg->wan_count];
                iface->type = IFACE_TYPE_WAN;
                strncpy(iface->ifname, ifname, IF_NAMESIZE - 1);
                parse_mac(mac_str, iface->mac);
                if (parse_ip_cidr(ip_cidr, &iface->ip, &iface->netmask, &iface->network) != 0) {
                    fprintf(stderr, "Invalid IP/CIDR for WAN %s: %s\n", ifname, ip_cidr);
                    fclose(fp);
                    return -1;
                }
                iface->enabled = 1;
                cfg->wan_count++;
            }
        }
    }

    fclose(fp);

    if (cfg->local_count == 0) {
        fprintf(stderr, "No LOCAL interfaces defined\n");
        return -1;
    }
    if (cfg->wan_count == 0) {
        fprintf(stderr, "No WAN interfaces defined\n");
        return -1;
    }

    return 0;
}

// Helper to convert IP to string
static const char *ip_to_str(uint32_t ip, char *buf, size_t len)
{
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, len);
    return buf;
}

void config_print(struct app_config *cfg)
{
    char ip_buf[INET_ADDRSTRLEN];
    char net_buf[INET_ADDRSTRLEN];

    printf("=== Configuration ===\n");
    printf("BPF File: %s\n", cfg->bpf_file);
    printf("Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           cfg->gateway_mac[0], cfg->gateway_mac[1], cfg->gateway_mac[2],
           cfg->gateway_mac[3], cfg->gateway_mac[4], cfg->gateway_mac[5]);

    printf("\nLOCAL interfaces (%d):\n", cfg->local_count);
    for (int i = 0; i < cfg->local_count; i++) {
        struct iface_config *iface = &cfg->locals[i];
        printf("  [%d] %s\n", i, iface->ifname);
        printf("      MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               iface->mac[0], iface->mac[1], iface->mac[2],
               iface->mac[3], iface->mac[4], iface->mac[5]);
        printf("      IP: %s\n", ip_to_str(iface->ip, ip_buf, sizeof(ip_buf)));
        printf("      Network: %s\n", ip_to_str(iface->network, net_buf, sizeof(net_buf)));
    }

    printf("\nWAN interfaces (%d):\n", cfg->wan_count);
    for (int i = 0; i < cfg->wan_count; i++) {
        struct iface_config *iface = &cfg->wans[i];
        printf("  [%d] %s\n", i, iface->ifname);
        printf("      MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               iface->mac[0], iface->mac[1], iface->mac[2],
               iface->mac[3], iface->mac[4], iface->mac[5]);
        printf("      IP: %s\n", ip_to_str(iface->ip, ip_buf, sizeof(ip_buf)));
    }
    printf("=====================\n\n");
}
