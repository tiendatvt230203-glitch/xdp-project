#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN 6
#define AES_KEY_LEN 16
#define AES_IV_LEN 16

// LOCAL interface config
struct local_config {
    char ifname[IF_NAMESIZE];      // Interface name (enp7s0)
    uint32_t ip;                   // IP address
    uint32_t netmask;              // Netmask
    uint32_t network;              // Network (ip & netmask)
    uint8_t src_mac[MAC_LEN];      // Source MAC (this interface)
    uint8_t dst_mac[MAC_LEN];      // Dest MAC (client on other side)
};

// WAN interface config
struct wan_config {
    char ifname[IF_NAMESIZE];      // Interface name (enp5s0)
    uint8_t src_mac[MAC_LEN];      // Source MAC (this interface)
    uint8_t dst_mac[MAC_LEN];      // Dest MAC (next-hop)
};

// Global config
struct app_config {
    // LOCAL interfaces
    struct local_config locals[MAX_INTERFACES];
    int local_count;

    // WAN interfaces
    struct wan_config wans[MAX_INTERFACES];
    int wan_count;

    // BPF program file
    char bpf_file[256];

    // Encryption config (AES-128-CTR)
    int crypto_enabled;                    // 1 = enabled, 0 = disabled
    uint8_t crypto_key[AES_KEY_LEN];       // 16-byte AES key
    uint8_t crypto_iv[AES_IV_LEN];         // 16-byte base IV
    uint16_t fake_ethertype;               // Fake EtherType (2 bytes), e.g. 0x88B5
};

// Parse config file
int config_load(struct app_config *cfg, const char *filename);

// Print config for debugging
void config_print(struct app_config *cfg);

// Parse MAC string "xx:xx:xx:xx:xx:xx" to bytes
int parse_mac(const char *str, uint8_t *mac);

// Find LOCAL interface for a given dest IP
// Returns: index of LOCAL interface, or -1 if not found
int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip);

#endif
