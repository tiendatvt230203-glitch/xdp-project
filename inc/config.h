#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <net/if.h>

#define MAX_INTERFACES 16
#define MAC_LEN 6
#define AES_KEY_LEN 16
#define AES_IV_LEN 16
#define MAX_BATCH_SIZE  1024 // Số lượng gói tin tối đa xử lý cùng lúc


struct local_config {
    char ifname[IF_NAMESIZE];
    uint32_t ip;
    uint32_t netmask;
    uint32_t network;
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    uint32_t umem_mb;       // Kích thước của từng umem cho mỗi queue của card mạng
    uint32_t ring_size;     
    uint32_t batch_size;    // Số lượng gói tin xử lý đồng thời
    uint32_t frame_size;    // kích thước của một ô nhớ để chứa gói tin
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
};

struct app_config {
    uint32_t global_frame_size;
    uint32_t global_batch_size;

    struct local_config locals[MAX_INTERFACES]; // Mảng chứa các interface local
    int local_count; // Số lượng interface local

    struct wan_config wans[MAX_INTERFACES]; // Mảng chứa các interface wan
    int wan_count; // Số lượng interface wan

    char bpf_file[256]; // Đường dẫn đến các file xdp redirect.o (xdp_redirect.o, xdp_wan_redirect.o)

    int crypto_enabled; // Biến bật tắt chế độ mã hóa
    uint8_t crypto_key[AES_KEY_LEN]; // Mảng chứa khóa
    uint8_t crypto_iv[AES_IV_LEN]; // Mảng chưa nonce
    uint16_t fake_ethertype; // Fake EtherType (0x88B5) - 2 server quy ước sẵn
};

int config_load(struct app_config *cfg, const char *filename);
void config_print(struct app_config *cfg);
int parse_mac(const char *str, uint8_t *mac);
int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip);
int config_validate(struct app_config *cfg);

#endif
