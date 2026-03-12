#include "../inc/crypto_layer2.h"
#include "../inc/config.h"
#include <string.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    const int nonce_size = packet_crypto_get_nonce_size();
    const int l2_hdr_extra = nonce_size - 1;
    const int l2_enc_start = 13 + nonce_size;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    uint8_t proto_flag;
    uint16_t fake_etype;

    if (likely(ether_type == 0x0800)) {
        proto_flag = PROTO_FLAG_IPV4;
        fake_etype = packet_crypto_get_fake_ethertype_ipv4();
    }
    else if (ether_type == 0x86DD) {
        proto_flag = PROTO_FLAG_IPV6;
        fake_etype = packet_crypto_get_fake_ethertype_ipv6();
    }
    else {
        return (int)pkt_len;
    }

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;

    crypto_generate_nonce(counter, proto_flag, nonce, &nonce_len);

    /* 1 key duy nhất */
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    const size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    memmove(packet + l2_enc_start, packet + ETH_HEADER_SIZE, payload_len);
    crypto_write_counter(packet, nonce, nonce_size, (uint8_t)(fake_etype >> 8));

    /* GCM encrypt */
    uint8_t tag[AES128_GCM_TAG_SIZE];
    crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + l2_enc_start, (int)payload_len, tag);
    memcpy(packet + l2_enc_start + payload_len, tag, AES128_GCM_TAG_SIZE);
    
    return (int)(pkt_len + l2_hdr_extra + AES128_GCM_TAG_SIZE);
}

int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    const int nonce_size = packet_crypto_get_nonce_size();
    const int l2_enc_start = 13 + nonce_size;

    uint8_t proto_flag;
    uint8_t nonce[16];
    crypto_read_counter(packet, nonce_size, nonce, &proto_flag);
    const int is_ipv4 = (proto_flag == PROTO_FLAG_IPV4);

    size_t enc_len = pkt_len - l2_enc_start - AES128_GCM_TAG_SIZE;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    memcpy(tag, packet + l2_enc_start + enc_len, AES128_GCM_TAG_SIZE);

    /* 1 key duy nhất */
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t *work_ptr = packet + l2_enc_start;

    /* GCM decrypt */
    crypto_aes_gcm_decrypt(key, nonce, nonce_size, work_ptr, (int)enc_len, tag);

    /* Restore ethertype và move payload */
    int has_ethertype = (work_ptr[0] == 0x08 && work_ptr[1] == 0x00) ||
                        (work_ptr[0] == 0x86 && work_ptr[1] == 0xDD);
    if (has_ethertype) {
        packet[12] = work_ptr[0];
        packet[13] = work_ptr[1];
        memmove(packet + ETH_HEADER_SIZE, work_ptr + 2, enc_len - 2);
        return (int)(ETH_HEADER_SIZE + enc_len - 2);
    } else {
        packet[12] = is_ipv4 ? 0x08 : 0x86;
        packet[13] = is_ipv4 ? 0x00 : 0xDD;
        memmove(packet + ETH_HEADER_SIZE, work_ptr, enc_len);
        return (int)(ETH_HEADER_SIZE + enc_len);
    }
}
