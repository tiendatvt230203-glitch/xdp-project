#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN 6
#define AES_KEY_LEN 32
#define AES_IV_LEN 16
#define MAX_BATCH_SIZE  1024

#define CRYPTO_MODE_CTR  0
#define CRYPTO_MODE_GCM  1

#define DEFAULT_FRAME_SIZE      4096
#define DEFAULT_BATCH_SIZE      1024
#define DEFAULT_UMEM_MB_LOCAL   2048
#define DEFAULT_UMEM_MB_WAN     256
#define DEFAULT_RING_SIZE       262144
#define DEFAULT_RING_SIZE_WAN   32768
#define DEFAULT_WINDOW_KB       2048
#define DEFAULT_QUEUE_COUNT     1
#define DEFAULT_LOCAL_RATE_LIMIT_MBPS 0

struct local_config {
    char ifname[IF_NAMESIZE];
    uint32_t ip;
    uint32_t netmask;
    uint32_t network;
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
    int queue_count;
};

struct wan_config {
    char ifname[IF_NAMESIZE];
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    uint32_t window_size;
    uint32_t umem_mb;
    uint32_t ring_size;
    uint32_t batch_size;
    uint32_t frame_size;
    int queue_count;
};

struct app_config {
    uint32_t global_frame_size;
    uint32_t global_batch_size;

    struct local_config locals[MAX_INTERFACES];
    int local_count;

    struct wan_config wans[MAX_INTERFACES];
    int wan_count;

    char bpf_file[256];

    int crypto_enabled;
    uint8_t crypto_key[AES_KEY_LEN];
    int encrypt_layer;
    uint16_t fake_ethertype_ipv4;
    uint16_t fake_ethertype_ipv6;
    uint8_t fake_protocol;
    uint32_t local_rate_limit_mbps;
    int crypto_mode;
    int nonce_size;
    int aes_bits;
};

int parse_mac(const char *str, uint8_t *mac);
int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network);
int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len);
int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip);
int config_validate(struct app_config *cfg);

#endif
