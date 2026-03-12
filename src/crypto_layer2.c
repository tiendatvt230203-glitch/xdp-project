#include "../inc/crypto_layer2.h"
#include "../inc/config.h"
#include <string.h>

/* Layer 2 Encrypt: Nhận packet → mã hóa → trả về length mới */
int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    const int nonce_size = packet_crypto_get_nonce_size();
    const int enc_start = 13 + nonce_size;
    const size_t payload_len = pkt_len - 14;
    
    /* Lấy key - 1 key duy nhất */
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    
    /* Tạo nonce từ counter */
    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16] = {0};
    nonce[0] = (counter >> 24) & 0xFF;
    nonce[1] = (counter >> 16) & 0xFF;
    nonce[2] = (counter >> 8) & 0xFF;
    nonce[3] = counter & 0xFF;
    
    /* Move payload */
    memmove(packet + enc_start, packet + 14, payload_len);
    
    /* Ghi marker + nonce */
    uint16_t fake_etype = packet_crypto_get_fake_ethertype_ipv4();
    packet[12] = (uint8_t)(fake_etype >> 8);
    memcpy(packet + 13, nonce, nonce_size);
    
    /* Encrypt + tag */
    uint8_t tag[16];
    crypto_aes_gcm_encrypt(key, nonce, nonce_size, packet + enc_start, (int)payload_len, tag);
    memcpy(packet + enc_start + payload_len, tag, 16);
    
    return (int)(pkt_len + nonce_size - 1 + 16);
}

/* Layer 2 Decrypt: Nhận packet → giải mã → trả về length mới */
int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    const int nonce_size = packet_crypto_get_nonce_size();
    const int enc_start = 13 + nonce_size;
    const size_t enc_len = pkt_len - enc_start - 16;
    
    /* Lấy key - 1 key duy nhất */
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    
    /* Đọc nonce từ packet */
    uint8_t nonce[16] = {0};
    memcpy(nonce, packet + 13, nonce_size);
    
    /* Đọc tag */
    uint8_t tag[16];
    memcpy(tag, packet + enc_start + enc_len, 16);
    
    /* Decrypt */
    crypto_aes_gcm_decrypt(key, nonce, nonce_size, packet + enc_start, (int)enc_len, tag);
    
    /* Restore ethertype + move payload */
    uint8_t *data = packet + enc_start;
    packet[12] = data[0];
    packet[13] = data[1];
    memmove(packet + 14, data + 2, enc_len - 2);
    
    return (int)(14 + enc_len - 2);
}
