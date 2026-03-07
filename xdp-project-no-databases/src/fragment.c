#define _POSIX_C_SOURCE 199309L
#include "../inc/fragment.h"
#include "../inc/packet_crypto.h"
#include "../inc/crypto_layer3.h"
#include "../inc/config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

static atomic_uint_fast32_t g_pkt_id_counter = 0;

uint16_t frag_next_pkt_id(void) {
    return (uint16_t)(atomic_fetch_add(&g_pkt_id_counter, 1) & 0xFFFF);
}

void frag_table_init(struct frag_table *ft) {
    memset(ft, 0, sizeof(*ft));
}

static uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void frag_table_gc(struct frag_table *ft) {
    uint64_t now = get_time_ns();
    for (int i = 0; i < FRAG_TABLE_SIZE; i++) {
        if (ft->entries[i].valid &&
            (now - ft->entries[i].timestamp_ns) > FRAG_TIMEOUT_NS) {
            ft->entries[i].valid = 0;
        }
    }
}

static void frag_write_hdr(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
}

static void frag_read_hdr(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int frag_is_fragment(const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index) {
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int nonce_size = packet_crypto_get_nonce_size();

    if (pkt_len < (uint32_t)(14 + 20 + tunnel_hdr_size + FRAG_HDR_SIZE))
        return 0;

    uint8_t ip_proto = pkt_data[14 + 9];
    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    if (ip_proto != fake_proto)
        return 0;

    int tunnel_off = 14 + 20;
    uint8_t orig_proto_byte = pkt_data[tunnel_off + nonce_size];

    if (!(orig_proto_byte & FRAG_FLAG_BIT))
        return 0;

    frag_read_hdr(pkt_data + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);
    return 1;
}

static int build_and_encrypt_fragment(struct packet_crypto_ctx *ctx,
                                       const uint8_t *eth_hdr,
                                       const uint8_t *ip_hdr,
                                       int ip_hdr_len,
                                       const uint8_t *payload,
                                       uint32_t payload_len,
                                       uint8_t orig_proto,
                                       uint16_t pkt_id,
                                       uint8_t frag_index,
                                       uint8_t *out_buf,
                                       uint32_t *out_len) {
    int offset = 0;
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();

    memcpy(out_buf, eth_hdr, 14);
    offset += 14;

    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;

    memcpy(out_buf + offset, payload, payload_len);
    offset += payload_len;

    uint16_t ip_total = (uint16_t)(ip_hdr_len + payload_len);
    out_buf[14 + 2] = (uint8_t)(ip_total >> 8);
    out_buf[14 + 3] = (uint8_t)(ip_total & 0xFF);

    out_buf[14 + 9] = orig_proto;

    out_buf[14 + 10] = 0;
    out_buf[14 + 11] = 0;
    uint16_t cksum = crypto_calc_ip_checksum(out_buf + 14, ip_hdr_len);
    out_buf[14 + 10] = (uint8_t)(cksum >> 8);
    out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);

    uint32_t pkt_len = (uint32_t)offset;

    packet_crypto_update_keys(ctx);

    uint16_t ether_type = ((uint16_t)out_buf[12] << 8) | out_buf[13];
    uint8_t proto_flag;
    int tunnel_off;

    if (ether_type == 0x0800) {
        proto_flag = PROTO_FLAG_IPV4;
        tunnel_off = 14 + ip_hdr_len;
    } else if (ether_type == 0x86DD) {
        proto_flag = PROTO_FLAG_IPV6;
        tunnel_off = 14 + 40;
    } else {
        return -1;
    }

    size_t transport_len = pkt_len - tunnel_off;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;

    crypto_generate_nonce(counter, proto_flag, nonce, &nonce_len);

    memmove(out_buf + tunnel_off + tunnel_hdr_size + FRAG_HDR_SIZE,
            out_buf + tunnel_off,
            transport_len);

    uint8_t flagged_proto = orig_proto | FRAG_FLAG_BIT;
    crypto_write_l3_tunnel_header(out_buf + tunnel_off, nonce, nonce_size, flagged_proto);

    frag_write_hdr(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    if (proto_flag == PROTO_FLAG_IPV4) {
        out_buf[14 + 9] = fake_proto;
    } 
    
    else {
        out_buf[14 + 6] = fake_proto;
    }

    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_HDR_SIZE;
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key) return -1;

    int hdr_overhead = tunnel_hdr_size + FRAG_HDR_SIZE;

    if (is_gcm) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                    out_buf + enc_off, (int)transport_len, tag) != 0) {
            return -1;
        }
        memcpy(out_buf + enc_off + transport_len, tag, AES128_GCM_TAG_SIZE);
        hdr_overhead += AES128_GCM_TAG_SIZE;
    } 
    
    else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv,
                                     out_buf + enc_off,
                                     (int)transport_len) != 0) {
            return -1;
        }
    }

    if (proto_flag == PROTO_FLAG_IPV4) {
        uint16_t old_totlen = ((uint16_t)out_buf[14 + 2] << 8) | out_buf[14 + 3];
        uint16_t new_totlen = old_totlen + (uint16_t)hdr_overhead;
        out_buf[14 + 2] = (uint8_t)(new_totlen >> 8);
        out_buf[14 + 3] = (uint8_t)(new_totlen & 0xFF);

        out_buf[14 + 10] = 0;
        out_buf[14 + 11] = 0;
        cksum = crypto_calc_ip_checksum(out_buf + 14, ip_hdr_len);
        out_buf[14 + 10] = (uint8_t)(cksum >> 8);
        out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);
    } 
    
    else {
        uint16_t old_paylen = ((uint16_t)out_buf[14 + 4] << 8) | out_buf[14 + 5];
        uint16_t new_paylen = old_paylen + (uint16_t)hdr_overhead;
        out_buf[14 + 4] = (uint8_t)(new_paylen >> 8);
        out_buf[14 + 5] = (uint8_t)(new_paylen & 0xFF);
    }

    *out_len = pkt_len + (uint32_t)hdr_overhead;
    return 0;
}

int frag_split_and_encrypt(struct packet_crypto_ctx *ctx,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint8_t *frag1, uint32_t *frag1_len,
                           uint8_t *frag2, uint32_t *frag2_len) {
    if (pkt_len < 14 + 20)
        return -1;

    const uint8_t *eth_hdr = pkt_data;
    const uint8_t *ip_hdr = pkt_data + 14;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    int ip_hdr_len;

    if (ether_type == 0x0800) {
        ip_hdr_len = (ip_hdr[0] & 0x0F) * 4;
        if (ip_hdr_len < 20) return -1;
    } 
    
    else if (ether_type == 0x86DD) {
        ip_hdr_len = 40;
    } 
    
    else {
        return -1;
    }

    if (pkt_len < (uint32_t)(14 + ip_hdr_len))
        return -1;

    uint8_t orig_proto;
    if (ether_type == 0x0800) {
        orig_proto = ip_hdr[9];
    } 
    
    else {
        orig_proto = ip_hdr[6];
    }

    const uint8_t *payload = pkt_data + 14 + ip_hdr_len;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len;

    uint32_t half1 = payload_len / 2;
    uint32_t half2 = payload_len - half1;

    uint16_t pkt_id = frag_next_pkt_id();

    if (build_and_encrypt_fragment(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                    payload, half1, orig_proto,
                                    pkt_id, 0,
                                    frag1, frag1_len) != 0) {
        return -1;
    }

    if (build_and_encrypt_fragment(ctx, eth_hdr, ip_hdr, ip_hdr_len,
                                    payload + half1, half2, orig_proto,
                                    pkt_id, 1,
                                    frag2, frag2_len) != 0) {
        return -1;
    }

    return 0;
}

int frag_decrypt_fragment(struct packet_crypto_ctx *ctx,
                          uint8_t *packet, size_t pkt_len,
                          uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();

    if (pkt_len < (size_t)(14 + 20 + tunnel_hdr_size + FRAG_HDR_SIZE))
        return -1;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    uint8_t fake_proto = packet_crypto_get_fake_protocol();
    uint8_t proto_flag;
    int tunnel_off;
    int ip_hdr_len;
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);

    if (ether_type == 0x0800) {
        if (packet[14 + 9] != fake_proto) return -1;
        proto_flag = PROTO_FLAG_IPV4;
        ip_hdr_len = (packet[14] & 0x0F) * 4;
        tunnel_off = 14 + ip_hdr_len;
    } 
    
    else if (ether_type == 0x86DD) {
        if (packet[14 + 6] != fake_proto) return -1;
        proto_flag = PROTO_FLAG_IPV6;
        ip_hdr_len = 40;
        tunnel_off = 14 + 40;
    } 
    
    else {
        return -1;
    }

    uint8_t rd_proto_flag, orig_proto_raw;
    uint8_t nonce[16];
    crypto_read_l3_tunnel_header(packet + tunnel_off, nonce_size,
                                  nonce, &rd_proto_flag, &orig_proto_raw);

    uint8_t orig_proto = orig_proto_raw & ~FRAG_FLAG_BIT;

    frag_read_hdr(packet + tunnel_off + tunnel_hdr_size, out_pkt_id, out_frag_index);

    int nonce_len;
    if (is_gcm) {
        nonce_len = nonce_size;
    } 
    
    else {
        nonce_len = AES128_IV_SIZE;
    }

    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_HDR_SIZE;
    size_t total_after_hdr = pkt_len - enc_off;

    size_t enc_len;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    if (is_gcm) {
        if (total_after_hdr < AES128_GCM_TAG_SIZE) return -1;
        enc_len = total_after_hdr - AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    } 
    
    else {
        enc_len = total_after_hdr;
    }

    uint8_t backup[2048];
    int has_backup = 0;
    if (enc_len <= sizeof(backup)) {
        memcpy(backup, packet + enc_off, enc_len);
        has_backup = 1;
    }

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };
    int hdr_overhead = tunnel_hdr_size + FRAG_HDR_SIZE + (is_gcm ? AES128_GCM_TAG_SIZE : 0);

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key) continue;

        if (k > 0 && has_backup) {
            memcpy(packet + enc_off, backup, enc_len);
        }

        if (is_gcm) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len,
                                        packet + enc_off, (int)enc_len, tag) != 0) {
                continue;
            }
        } 
        
        else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, packet + enc_off, (int)enc_len) != 0)
                continue;

            if (*out_frag_index == 0 && (orig_proto == 6 || orig_proto == 17)) {
                if (enc_len >= 4) {
                    uint16_t src_port = ((uint16_t)packet[enc_off] << 8) | packet[enc_off + 1];
                    uint16_t dst_port = ((uint16_t)packet[enc_off + 2] << 8) | packet[enc_off + 3];
                    if (src_port == 0 && dst_port == 0)
                        continue;
                }
            }
        }

        memmove(packet + tunnel_off, packet + enc_off, enc_len);

        if (proto_flag == PROTO_FLAG_IPV4) {
            packet[14 + 9] = orig_proto;
            uint16_t old_totlen = ((uint16_t)packet[14 + 2] << 8) | packet[14 + 3];
            uint16_t new_totlen = old_totlen - (uint16_t)hdr_overhead;
            packet[14 + 2] = (uint8_t)(new_totlen >> 8);
            packet[14 + 3] = (uint8_t)(new_totlen & 0xFF);

            packet[14 + 10] = 0;
            packet[14 + 11] = 0;
            uint16_t cksum = crypto_calc_ip_checksum(packet + 14, ip_hdr_len);
            packet[14 + 10] = (uint8_t)(cksum >> 8);
            packet[14 + 11] = (uint8_t)(cksum & 0xFF);
        } 
        
        else {
            packet[14 + 6] = orig_proto;
            uint16_t old_paylen = ((uint16_t)packet[14 + 4] << 8) | packet[14 + 5];
            uint16_t new_paylen = old_paylen - (uint16_t)hdr_overhead;
            packet[14 + 4] = (uint8_t)(new_paylen >> 8);
            packet[14 + 5] = (uint8_t)(new_paylen & 0xFF);
        }

        return (int)(pkt_len - hdr_overhead);
    }

    return -1;
}

int frag_try_reassemble(struct frag_table *ft,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t pkt_id, uint8_t frag_index,
                        uint8_t *out_buf, uint32_t *out_len) {
    if (pkt_len < 14 + 20)
        return -1;

    uint16_t ether_type = ((uint16_t)pkt_data[12] << 8) | pkt_data[13];
    int ip_hdr_len;
    if (ether_type == 0x0800) {
        ip_hdr_len = (pkt_data[14] & 0x0F) * 4;
    } 
    
    else if (ether_type == 0x86DD) {
        ip_hdr_len = 40;
    } 
    
    else {
        return -1;
    }

    const uint8_t *payload = pkt_data + 14 + ip_hdr_len;
    uint32_t payload_len = pkt_len - 14 - ip_hdr_len;

    int idx = pkt_id % FRAG_TABLE_SIZE;
    struct frag_entry *entry = &ft->entries[idx];
    uint64_t now = get_time_ns();

    if (frag_index == 0) {
        entry->pkt_id = pkt_id;
        entry->data_len = payload_len;
        if (payload_len > sizeof(entry->data)) {
            return -1;
        }
        memcpy(entry->data, payload, payload_len);
        memcpy(entry->eth_hdr, pkt_data, 14);
        memcpy(entry->ip_hdr, pkt_data + 14, ip_hdr_len);
        entry->ip_hdr_len = ip_hdr_len;
        entry->orig_proto = pkt_data[14 + 9];
        entry->timestamp_ns = now;
        entry->valid = 1;
        return 0;
    }

    if (frag_index == 1) {
        if (!entry->valid || entry->pkt_id != pkt_id) {
            return -1;
        }

        if ((now - entry->timestamp_ns) > FRAG_TIMEOUT_NS) {
            entry->valid = 0;
            return -1;
        }

        uint32_t total_payload = entry->data_len + payload_len;
        uint32_t total_pkt = 14 + entry->ip_hdr_len + total_payload;

        if (total_pkt > 4096) {
            entry->valid = 0;
            return -1;
        }

        int off = 0;

        memcpy(out_buf, entry->eth_hdr, 14);
        off += 14;

        memcpy(out_buf + off, entry->ip_hdr, entry->ip_hdr_len);
        off += entry->ip_hdr_len;

        memcpy(out_buf + off, entry->data, entry->data_len);
        off += entry->data_len;

        memcpy(out_buf + off, payload, payload_len);
        off += payload_len;

        if (ether_type == 0x0800) {
            uint16_t ip_total = (uint16_t)(entry->ip_hdr_len + total_payload);
            out_buf[14 + 2] = (uint8_t)(ip_total >> 8);
            out_buf[14 + 3] = (uint8_t)(ip_total & 0xFF);

            out_buf[14 + 10] = 0;
            out_buf[14 + 11] = 0;
            uint16_t cksum = crypto_calc_ip_checksum(out_buf + 14, entry->ip_hdr_len);
            out_buf[14 + 10] = (uint8_t)(cksum >> 8);
            out_buf[14 + 11] = (uint8_t)(cksum & 0xFF);
        } 
        
        else {
            uint16_t ipv6_paylen = (uint16_t)total_payload;
            out_buf[14 + 4] = (uint8_t)(ipv6_paylen >> 8);
            out_buf[14 + 5] = (uint8_t)(ipv6_paylen & 0xFF);
        }

        *out_len = (uint32_t)off;
        entry->valid = 0;
        return 1;
    }

    return -1;
}
