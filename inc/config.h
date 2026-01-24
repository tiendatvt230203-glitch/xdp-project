#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN 6

// Interface type
#define IFACE_TYPE_LOCAL  1  // Receive via XDP redirect
#define IFACE_TYPE_WAN    2  // Send out

// Interface config entry
struct iface_config {
    int type;                      // LOCAL or WAN
    char ifname[IF_NAMESIZE];      // Interface name
    uint8_t mac[MAC_LEN];          // MAC address
    uint32_t ip;                   // IP address (network byte order)
    uint32_t netmask;              // Netmask (network byte order)
    uint32_t network;              // Network address (ip & netmask)
    int enabled;                   // Is enabled
};

// Global config
struct app_config {
    struct iface_config locals[MAX_INTERFACES];
    int local_count;

    struct iface_config wans[MAX_INTERFACES];
    int wan_count;

    uint8_t gateway_mac[MAC_LEN];  // Gateway MAC for WAN

    char bpf_file[256];            // BPF program file
};

// Parse config file
int config_load(struct app_config *cfg, const char *filename);

// Print config for debugging
void config_print(struct app_config *cfg);

// Parse MAC string "xx:xx:xx:xx:xx:xx" to bytes
int parse_mac(const char *str, uint8_t *mac);

#endif
