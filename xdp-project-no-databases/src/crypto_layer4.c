#include "../inc/crypto_layer4.h"
#include "../inc/config.h"
#include <string.h>

#define MIN_ETH_PKT       (ETH_HEADER_SIZE + 20 + 8)

#define IPV4_PROTO_OFF     (ETH_HEADER_SIZE + 9)
#define IPV4_TOTLEN_OFF    (ETH_HEADER_SIZE + 2)
#define IPV4_CKSUM_OFF     (ETH_HEADER_SIZE + 10)

#define L4_TUNNEL_MAGIC    0xA5

#define L4_MAX_FRAME      1514

static void l4_write_tunnel_header(uint8_t *buf, const uint8_t *nonce,
                                    int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = L4_TUNNEL_MAGIC;
}

static void l4_read_tunnel_header(const uint8_t *buf, int nonce_size,
                                   uint8_t *nonce_out, uint8_t *proto_flag) {
    memcpy(nonce_out, buf, nonce_size);
    if (proto_flag) *proto_flag = nonce_out[0] >> 7;
}

static int l4_is_tunnel_header(const uint8_t *buf, int nonce_size) {
    if (buf[nonce_size] != L4_TUNNEL_MAGIC) return 0;
    if ((buf[0] & 0x80) != 0) return 0;
    return 1;
}

static int get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto, size_t remaining) {
    if (ip_proto == 6) {
        if (remaining < 20) return -1;
        int data_off = ((transport_hdr[12] >> 4) & 0x0F) * 4;
        if (data_off < 20 || (size_t)data_off > remaining) return -1;
        return data_off;
    } 
    
    else if (ip_proto == 17) {
        if (remaining < 8) return -1;
        return 8;
    }
    return -1;
}

int crypto_layer4_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT) return -1;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    if (ether_type != 0x0800) return (int)pkt_len;

    uint8_t ip_proto = packet[IPV4_PROTO_OFF];
    if (ip_proto != 6 && ip_proto != 17) return (int)pkt_len;

    int ip_hdr_len = (packet[ETH_HEADER_SIZE] & 0x0F) * 4;
    if (ip_hdr_len < 20) return -1;

    int transport_off = ETH_HEADER_SIZE + ip_hdr_len;
    size_t remaining = pkt_len - transport_off;

    int transport_hdr_size = get_transport_hdr_size(packet + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0) return -1;

    int app_off = transport_off + transport_hdr_size;
    size_t app_len = pkt_len - app_off;
    if (app_len == 0) return (int)pkt_len;

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    uint32_t counter = packet_crypto_next_counter();

    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);

    if (is_gcm) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + app_off, (int)app_len, tag) != 0) return -1;
        memmove(packet + app_off + tunnel_hdr_size, packet + app_off, app_len);
        memcpy(packet + app_off + tunnel_hdr_size + app_len, tag, AES128_GCM_TAG_SIZE);
    } 
    
    else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, packet + app_off, (int)app_len) != 0) return -1;
        memmove(packet + app_off + tunnel_hdr_size, packet + app_off, app_len);
    }

    l4_write_tunnel_header(packet + app_off, nonce, nonce_size);

    int total_overhead = tunnel_hdr_size + (is_gcm ? AES128_GCM_TAG_SIZE : 0);
    uint16_t old_totlen = ((uint16_t)packet[IPV4_TOTLEN_OFF] << 8) | packet[IPV4_TOTLEN_OFF + 1];
    uint16_t new_totlen = old_totlen + (uint16_t)total_overhead;
    packet[IPV4_TOTLEN_OFF] = (uint8_t)(new_totlen >> 8);
    packet[IPV4_TOTLEN_OFF + 1] = (uint8_t)(new_totlen & 0xFF);
    packet[IPV4_CKSUM_OFF] = 0; packet[IPV4_CKSUM_OFF + 1] = 0;
    uint16_t cksum = crypto_calc_ip_checksum(packet + ETH_HEADER_SIZE, ip_hdr_len);
    packet[IPV4_CKSUM_OFF] = (uint8_t)(cksum >> 8);
    packet[IPV4_CKSUM_OFF + 1] = (uint8_t)(cksum & 0xFF);

    return (int)(pkt_len + total_overhead);
}

int crypto_layer4_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT) return -1;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    if (ether_type != 0x0800) return (int)pkt_len;

    uint8_t ip_proto = packet[IPV4_PROTO_OFF];
    if (ip_proto != 6 && ip_proto != 17) return (int)pkt_len;

    int ip_hdr_len = (packet[ETH_HEADER_SIZE] & 0x0F) * 4;
    if (ip_hdr_len < 20) return -1;

    int transport_off = ETH_HEADER_SIZE + ip_hdr_len;
    size_t remaining = pkt_len - transport_off;

    int transport_hdr_size = get_transport_hdr_size(packet + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0) return (int)pkt_len;

    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = transport_off + transport_hdr_size;

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size) || !l4_is_tunnel_header(packet + tunnel_off, nonce_size))
        return (int)pkt_len;

    uint8_t proto_flag;
    uint8_t nonce[16];
    l4_read_tunnel_header(packet + tunnel_off, nonce_size, nonce, &proto_flag);
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);

    int nonce_len;
    if (is_gcm) {
        nonce_len = nonce_size;
    } 
    
    else {
        nonce_len = AES128_IV_SIZE;
    }

    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t total_after_tunnel = pkt_len - enc_off;
    size_t enc_len;
    uint8_t tag[AES128_GCM_TAG_SIZE];

    if (is_gcm) {
        if (total_after_tunnel < AES128_GCM_TAG_SIZE) return -1;
        enc_len = total_after_tunnel - AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    } 
    
    else enc_len = total_after_tunnel;

    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    if (has_backup) memcpy(backup, packet + enc_off, enc_len);

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
    int total_overhead = tunnel_hdr_size + (is_gcm ? AES128_GCM_TAG_SIZE : 0);

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key) continue;

        uint8_t *work_ptr = packet + enc_off;
        if (k > 0 && has_backup) memcpy(work_ptr, backup, enc_len);

        if (is_gcm) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0) continue;
        } 
        
        else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0) continue;
        }

        memmove(packet + tunnel_off, work_ptr, enc_len);

        uint16_t old_totlen = ((uint16_t)packet[IPV4_TOTLEN_OFF] << 8) | packet[IPV4_TOTLEN_OFF + 1];
        uint16_t new_totlen = old_totlen - (uint16_t)total_overhead;
        packet[IPV4_TOTLEN_OFF] = (uint8_t)(new_totlen >> 8);
        packet[IPV4_TOTLEN_OFF + 1] = (uint8_t)(new_totlen & 0xFF);
        packet[IPV4_CKSUM_OFF] = 0; packet[IPV4_CKSUM_OFF + 1] = 0;
        uint16_t cksum = crypto_calc_ip_checksum(packet + ETH_HEADER_SIZE, ip_hdr_len);
        packet[IPV4_CKSUM_OFF] = (uint8_t)(cksum >> 8);
        packet[IPV4_CKSUM_OFF + 1] = (uint8_t)(cksum & 0xFF);

        return (int)(pkt_len - total_overhead);
    }
    return -1;
}
