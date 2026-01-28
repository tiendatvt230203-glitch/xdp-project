#include "../inc/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

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

static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network)
{
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

static char *trim(char *str)
{
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static const char *ip_to_str(uint32_t ip, char *buf, size_t len)
{
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, len);
    return buf;
}

static const char *mac_to_str(const uint8_t *mac, char *buf, size_t len)
{
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static int parse_hex_bytes(const char *str, uint8_t *out, int expected_len)
{
    int len = strlen(str);
    if (len != expected_len * 2) {
        return -1;
    }

    for (int i = 0; i < expected_len; i++) {
        unsigned int val;
        if (sscanf(str + i * 2, "%2x", &val) != 1) {
            return -1;
        }
        out[i] = (uint8_t)val;
    }
    return 0;
}

static const char *bytes_to_hex(const uint8_t *data, int len, char *buf, size_t buflen)
{
    if (buflen < (size_t)(len * 2 + 1)) {
        buf[0] = '\0';
        return buf;
    }
    for (int i = 0; i < len; i++) {
        sprintf(buf + i * 2, "%02x", data[i]);
    }
    return buf;
}

int config_load(struct app_config *cfg, const char *filename)
{
    FILE *fp;
    char line[512];

    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->bpf_file, "bpf/xdp_redirect.o", sizeof(cfg->bpf_file) - 1);

    fp = fopen(filename, "r");
    if (!fp) {
        perror("fopen config");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *trimmed = trim(line);

        if (trimmed[0] == '#' || trimmed[0] == '\0')
            continue;

        if (strncmp(trimmed, "LOCAL ", 6) == 0 && cfg->local_count < MAX_INTERFACES) {
            char ifname[IF_NAMESIZE], ip_cidr[64], src_mac_str[32], dst_mac_str[32];
            int umem_mb = 0;

            int parsed = sscanf(trimmed, "LOCAL %15s %63s %31s %31s %d",
                       ifname, ip_cidr, src_mac_str, dst_mac_str, &umem_mb);

            if (parsed < 5) {
                fprintf(stderr, "Invalid LOCAL config: umem_mb is required\n");
                fprintf(stderr, "Format: LOCAL <interface> <network/mask> <src_mac> <dst_mac> <umem_mb>\n");
                fclose(fp);
                return -1;
            }

            struct local_config *local = &cfg->locals[cfg->local_count];
            strncpy(local->ifname, ifname, IF_NAMESIZE - 1);

            if (parse_ip_cidr(ip_cidr, &local->ip, &local->netmask, &local->network) != 0) {
                fprintf(stderr, "Invalid LOCAL network: %s\n", ip_cidr);
                fclose(fp);
                return -1;
            }
            if (parse_mac(src_mac_str, local->src_mac) != 0) {
                fprintf(stderr, "Invalid LOCAL src_mac: %s\n", src_mac_str);
                fclose(fp);
                return -1;
            }
            if (parse_mac(dst_mac_str, local->dst_mac) != 0) {
                fprintf(stderr, "Invalid LOCAL dst_mac: %s\n", dst_mac_str);
                fclose(fp);
                return -1;
            }

            local->umem_mb = umem_mb;
            cfg->local_count++;
            continue;
        }

        if (strncmp(trimmed, "WAN ", 4) == 0 && cfg->wan_count < MAX_INTERFACES) {
            char ifname[IF_NAMESIZE], src_mac_str[32], dst_mac_str[32];
            int window_kb = 0;
            int umem_mb = 0;

            int parsed = sscanf(trimmed, "WAN %15s %31s %31s %d %d",
                               ifname, src_mac_str, dst_mac_str, &window_kb, &umem_mb);

            if (parsed < 5) {
                fprintf(stderr, "Invalid WAN config: window_kb and umem_mb are required\n");
                fprintf(stderr, "Format: WAN <interface> <src_mac> <dst_mac> <window_kb> <umem_mb>\n");
                fclose(fp);
                return -1;
            }

            struct wan_config *wan = &cfg->wans[cfg->wan_count];
            strncpy(wan->ifname, ifname, IF_NAMESIZE - 1);

            if (parse_mac(src_mac_str, wan->src_mac) != 0) {
                fprintf(stderr, "Invalid WAN src_mac: %s\n", src_mac_str);
                fclose(fp);
                return -1;
            }

            if (parse_mac(dst_mac_str, wan->dst_mac) != 0) {
                fprintf(stderr, "Invalid WAN dst_mac: %s\n", dst_mac_str);
                fclose(fp);
                return -1;
            }

            wan->window_size = window_kb * 1024;
            wan->umem_mb = umem_mb;
            cfg->wan_count++;
            continue;
        }

        if (strncmp(trimmed, "BPF_FILE ", 9) == 0) {
            sscanf(trimmed, "BPF_FILE %255s", cfg->bpf_file);
            continue;
        }

        if (strncmp(trimmed, "CRYPTO_ENABLED ", 15) == 0) {
            int enabled;
            if (sscanf(trimmed, "CRYPTO_ENABLED %d", &enabled) == 1) {
                cfg->crypto_enabled = enabled ? 1 : 0;
            }
            continue;
        }

        if (strncmp(trimmed, "CRYPTO_KEY ", 11) == 0) {
            char key_hex[64];
            if (sscanf(trimmed, "CRYPTO_KEY %63s", key_hex) == 1) {
                if (parse_hex_bytes(key_hex, cfg->crypto_key, AES_KEY_LEN) != 0) {
                    fprintf(stderr, "Invalid CRYPTO_KEY: must be 32 hex characters\n");
                    fclose(fp);
                    return -1;
                }
            }
            continue;
        }

        if (strncmp(trimmed, "CRYPTO_IV ", 10) == 0) {
            char iv_hex[64];
            if (sscanf(trimmed, "CRYPTO_IV %63s", iv_hex) == 1) {
                if (parse_hex_bytes(iv_hex, cfg->crypto_iv, AES_IV_LEN) != 0) {
                    fprintf(stderr, "Invalid CRYPTO_IV: must be 32 hex characters\n");
                    fclose(fp);
                    return -1;
                }
            }
            continue;
        }

        if (strncmp(trimmed, "FAKE_ETHERTYPE ", 15) == 0) {
            char type_hex[16];
            if (sscanf(trimmed, "FAKE_ETHERTYPE %15s", type_hex) == 1) {
                unsigned int val;
                if (sscanf(type_hex, "%x", &val) == 1 && val <= 0xFFFF) {
                    cfg->fake_ethertype = (uint16_t)val;
                } else {
                    fprintf(stderr, "Invalid FAKE_ETHERTYPE: must be 4 hex characters (e.g. 88B5)\n");
                    fclose(fp);
                    return -1;
                }
            }
            continue;
        }
    }

    fclose(fp);

    if (cfg->local_count == 0) {
        fprintf(stderr, "No LOCAL interface defined\n");
        return -1;
    }
    if (cfg->wan_count == 0) {
        fprintf(stderr, "No WAN interface defined\n");
        return -1;
    }

    return 0;
}

int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip)
{
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];
        if ((dest_ip & local->netmask) == local->network) {
            return i;
        }
    }
    return -1;
}

void config_print(struct app_config *cfg)
{
    char ip_buf[INET_ADDRSTRLEN], ip_buf2[INET_ADDRSTRLEN];
    char mac_buf[32], mac_buf2[32];

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                    XDP FORWARDER CONFIG                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    printf("║ LOCAL Interfaces: %d                                          ║\n", cfg->local_count);
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];
        printf("╟──────────────────────────────────────────────────────────────╢\n");
        printf("║ [%d] %-58s ║\n", i, local->ifname);
        printf("║   Network: %-52s ║\n", ip_to_str(local->network, ip_buf, sizeof(ip_buf)));
        printf("║   Netmask: %-52s ║\n", ip_to_str(local->netmask, ip_buf2, sizeof(ip_buf2)));
        printf("║   SRC MAC: %-52s ║\n", mac_to_str(local->src_mac, mac_buf, sizeof(mac_buf)));
        printf("║   DST MAC: %-52s ║\n", mac_to_str(local->dst_mac, mac_buf2, sizeof(mac_buf2)));
        printf("║   UMEM:    %-52d ║\n", local->umem_mb);
    }

    printf("╠══════════════════════════════════════════════════════════════╣\n");

    printf("║ WAN Interfaces: %d                                            ║\n", cfg->wan_count);
    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *wan = &cfg->wans[i];
        printf("╟──────────────────────────────────────────────────────────────╢\n");
        printf("║ [%d] %-58s ║\n", i, wan->ifname);
        printf("║   SRC MAC: %-52s ║\n", mac_to_str(wan->src_mac, mac_buf, sizeof(mac_buf)));
        printf("║   DST MAC: %-52s ║\n", mac_to_str(wan->dst_mac, mac_buf2, sizeof(mac_buf2)));
        printf("║   Window:  %-52d ║\n", wan->window_size / 1024);
        printf("║   UMEM:    %-52d ║\n", wan->umem_mb);
    }

    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ BPF File: %-52s ║\n", cfg->bpf_file);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Encryption: AES-128-CTR %-38s ║\n", cfg->crypto_enabled ? "[ENABLED]" : "[DISABLED]");
    if (cfg->crypto_enabled) {
        char hex_buf[64];
        printf("║   Key: %s...  ║\n", bytes_to_hex(cfg->crypto_key, 8, hex_buf, sizeof(hex_buf)));
        printf("║   IV:  %s...  ║\n", bytes_to_hex(cfg->crypto_iv, 8, hex_buf, sizeof(hex_buf)));
        printf("║   Fake EtherType: 0x%04X %-36s ║\n", cfg->fake_ethertype,
               cfg->fake_ethertype ? "(obfuscated)" : "(disabled)");
    }
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}
