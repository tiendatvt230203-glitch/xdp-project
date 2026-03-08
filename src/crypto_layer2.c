#include "../inc/crypto_layer2.h"
#include "../inc/config.h"
#include <string.h>
#include <stdio.h>

#define MIN_ETH_PKT  (ETH_HEADER_SIZE + 8)



static int verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len) {
    if (len < 20) return 0;
    uint8_t ttl   = ip_payload[8];
    uint8_t proto = ip_payload[9];
    if (ttl == 0) return 0;
    if (proto == 1 || proto == 2 || proto == 6 || proto == 17 ||
        proto == 47 || proto == 50 || proto == 51 || proto == 58 ||
        proto == 89 || proto == 132)
        return 1;
    return 0;
}

static int verify_ipv6_after_decrypt(const uint8_t *ip_payload, size_t len) {
    if (len < 40) return 0;
    uint8_t next_hdr  = ip_payload[6];
    uint8_t hop_limit = ip_payload[7];
    if (hop_limit == 0) return 0;
    if (next_hdr == 6 || next_hdr == 17 || next_hdr == 58 ||
        next_hdr == 44 || next_hdr == 43 || next_hdr == 0 || next_hdr == 60)
        return 1;
    return 0;
}

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT) return -1;

    int nonce_size = packet_crypto_get_nonce_size();
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    size_t payload_len = pkt_len - ETH_HEADER_SIZE;  /* EtherType(2) + IP + ... */

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    uint8_t proto_flag;
    if (ether_type == 0x0800) {
        proto_flag = PROTO_FLAG_IPV4;
    } else if (ether_type == 0x86DD) {
        proto_flag = PROTO_FLAG_IPV6;
    } else {
        return (int)pkt_len;
    }

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, proto_flag, nonce, &nonce_len);


    memmove(packet + ETH_HEADER_SIZE + nonce_size, packet + ETH_HEADER_SIZE, payload_len);
    memcpy(packet + ETH_HEADER_SIZE, nonce, nonce_size);
    if (ether_type == 0x0800) {
        packet[12] = (uint8_t)(ETHERTYPE_L2_ENCRYPTED_IPV4 >> 8);
        packet[13] = (uint8_t)(ETHERTYPE_L2_ENCRYPTED_IPV4 & 0xFF);
    } else {
        packet[12] = (uint8_t)(ETHERTYPE_L2_ENCRYPTED_IPV6 >> 8);
        packet[13] = (uint8_t)(ETHERTYPE_L2_ENCRYPTED_IPV6 & 0xFF);
    }

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    int enc_off = ETH_HEADER_SIZE + nonce_size;

    if (is_gcm) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + enc_off, (int)payload_len, tag) != 0) return -1;
        memcpy(packet + enc_off + payload_len, tag, AES128_GCM_TAG_SIZE);
        return (int)(pkt_len + nonce_size + AES128_GCM_TAG_SIZE);
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)payload_len) != 0) return -1;
        return (int)(pkt_len + nonce_size);
    }
}

int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet) return -1;

    int nonce_size = packet_crypto_get_nonce_size();
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int enc_off = ETH_HEADER_SIZE + nonce_size;

    if (pkt_len < (size_t)enc_off) return -1;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    if (ether_type != ETHERTYPE_L2_ENCRYPTED_IPV4 && ether_type != ETHERTYPE_L2_ENCRYPTED_IPV6)
        return (int)pkt_len;

    uint8_t nonce[16];
    memcpy(nonce, packet + ETH_HEADER_SIZE, nonce_size);

    size_t enc_len = pkt_len - enc_off;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    if (is_gcm) {
        if (pkt_len < (size_t)(enc_off + AES128_GCM_TAG_SIZE)) return -1;
        enc_len -= AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    }

    int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;
    uint8_t backup[2048];
    if (enc_len <= sizeof(backup)) memcpy(backup, packet + enc_off, enc_len);

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key) continue;

        uint8_t *work_ptr = packet + enc_off;
        if (k > 0) memcpy(work_ptr, backup, enc_len);

        if (is_gcm) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) == 0) {
   
                packet[12] = work_ptr[0];
                packet[13] = work_ptr[1];
                memmove(packet + ETH_HEADER_SIZE, work_ptr + 2, enc_len - 2);
                return (int)(ETH_HEADER_SIZE + enc_len - 2);
            }
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) == 0) {
                int is_ipv4 = (work_ptr[0] == 0x08 && work_ptr[1] == 0x00);
                if (is_ipv4 ? verify_ipv4_after_decrypt(work_ptr, enc_len) : verify_ipv6_after_decrypt(work_ptr, enc_len)) {
                    packet[12] = work_ptr[0];
                    packet[13] = work_ptr[1];
                    memmove(packet + ETH_HEADER_SIZE, work_ptr + 2, enc_len - 2);
                    return (int)(ETH_HEADER_SIZE + enc_len - 2);
                }
            }
        }
    }
    return -1;
}