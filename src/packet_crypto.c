#include "packet_crypto.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <openssl/evp.h>

static uint8_t g_key[AES128_KEY_SIZE];
static uint8_t g_base_iv[AES128_IV_SIZE];
static uint16_t g_fake_ethertype = 0;
static volatile int g_initialized = 0;

static __thread EVP_CIPHER_CTX *tls_ctx = NULL;
static __thread int tls_cipher_ready = 0;

static EVP_CIPHER_CTX *get_ready_ctx(void) {
    if (!tls_ctx) {
        tls_ctx = EVP_CIPHER_CTX_new();
        if (!tls_ctx) return NULL;
    }

    if (!tls_cipher_ready) {
        if (EVP_EncryptInit_ex(tls_ctx, EVP_aes_128_ctr(), NULL, g_key, g_base_iv) != 1) {
            return NULL;
        }
        tls_cipher_ready = 1;
    }

    return tls_ctx;
}

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES128_KEY_SIZE],
                       const uint8_t base_iv[AES128_IV_SIZE]) {
    if (!ctx || !key) return -1;

    memcpy(g_key, key, AES128_KEY_SIZE);
    memcpy(ctx->round_key, key, AES128_KEY_SIZE);

    if (base_iv) {
        memcpy(g_base_iv, base_iv, AES128_IV_SIZE);
        memcpy(ctx->base_iv, base_iv, AES128_IV_SIZE);
    } else {
        memset(g_base_iv, 0, AES128_IV_SIZE);
        memset(ctx->base_iv, 0, AES128_IV_SIZE);
    }

    ctx->fake_ethertype = 0;
    ctx->initialized = true;
    g_initialized = 1;

    if (!get_ready_ctx()) {
        return -1;
    }

    return 0;
}

void packet_crypto_set_fake_ethertype(struct packet_crypto_ctx *ctx,
                                      uint16_t fake_ethertype) {
    if (!ctx) return;
    ctx->fake_ethertype = fake_ethertype;
    g_fake_ethertype = fake_ethertype;
}

/**
 * Build IV từ IP header (implicit nonce - không gửi đi)
 * IV = src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + protocol(1) + ip_id(2) + padding(1)
 */
static int build_iv_from_packet(const uint8_t *packet, size_t pkt_len, uint8_t iv[AES128_IV_SIZE]) {
    if (pkt_len < ETH_HEADER_SIZE + sizeof(struct iphdr))
        return -1;

    struct iphdr *ip = (struct iphdr *)(packet + ETH_HEADER_SIZE);
    int ip_hdr_len = ip->ihl * 4;

    uint16_t src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < ETH_HEADER_SIZE + ip_hdr_len + sizeof(struct tcphdr))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)(packet + ETH_HEADER_SIZE + ip_hdr_len);
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        if (pkt_len < ETH_HEADER_SIZE + ip_hdr_len + sizeof(struct udphdr))
            return -1;
        struct udphdr *udp = (struct udphdr *)(packet + ETH_HEADER_SIZE + ip_hdr_len);
        src_port = udp->source;
        dst_port = udp->dest;
    }

    /* Build 16-byte IV */
    memcpy(iv, &ip->saddr, 4);        /* [0-3]   src_ip */
    memcpy(iv + 4, &ip->daddr, 4);    /* [4-7]   dst_ip */
    memcpy(iv + 8, &src_port, 2);     /* [8-9]   src_port */
    memcpy(iv + 10, &dst_port, 2);    /* [10-11] dst_port */
    iv[12] = ip->protocol;            /* [12]    protocol */
    memcpy(iv + 13, &ip->id, 2);      /* [13-14] ip_id */
    iv[15] = 0x04;                    /* [15]    padding */

    /* XOR với base_iv */
    for (int i = 0; i < AES128_IV_SIZE; i++) {
        iv[i] ^= g_base_iv[i];
    }

    return 0;
}

/**
 * Lấy vị trí L4 payload
 */
static int get_payload_info(uint8_t *packet, size_t pkt_len,
                            uint8_t **payload_out, size_t *payload_len_out) {
    if (pkt_len < ETH_HEADER_SIZE + sizeof(struct iphdr))
        return -1;

    struct iphdr *ip = (struct iphdr *)(packet + ETH_HEADER_SIZE);
    int ip_hdr_len = ip->ihl * 4;
    int l4_offset = ETH_HEADER_SIZE + ip_hdr_len;
    int l4_hdr_len = 0;

    if (ip->protocol == IPPROTO_TCP) {
        if (pkt_len < l4_offset + sizeof(struct tcphdr))
            return -1;
        struct tcphdr *tcp = (struct tcphdr *)(packet + l4_offset);
        l4_hdr_len = tcp->doff * 4;
    } else if (ip->protocol == IPPROTO_UDP) {
        l4_hdr_len = sizeof(struct udphdr);
    }

    int payload_offset = l4_offset + l4_hdr_len;
    if (payload_offset > (int)pkt_len)
        return -1;

    *payload_out = packet + payload_offset;
    *payload_len_out = pkt_len - payload_offset;

    return 0;
}

static int fast_aes_ctr(const uint8_t *iv, uint8_t *data, int len) {
    if (len <= 0) return 0;

    EVP_CIPHER_CTX *evp = get_ready_ctx();
    if (!evp) return -1;

    int out_len;

    if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, iv) != 1) {
        return -1;
    }

    if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) {
        return -1;
    }

    return 0;
}

int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet) return -1;

    /* Build IV từ IP header */
    uint8_t iv[AES128_IV_SIZE];
    if (build_iv_from_packet(packet, pkt_len, iv) != 0) {
        return -1;
    }

    /* Lấy L4 payload */
    uint8_t *payload;
    size_t payload_len;
    if (get_payload_info(packet, pkt_len, &payload, &payload_len) != 0) {
        return -1;
    }

    /* Encrypt L4 payload */
    if (fast_aes_ctr(iv, payload, (int)payload_len) != 0) {
        return -1;
    }

    /* Đổi EtherType: 0x0800 → 0x88B5 */
    if (g_fake_ethertype != 0) {
        packet[12] = (g_fake_ethertype >> 8) & 0xFF;
        packet[13] = g_fake_ethertype & 0xFF;
    }

    return 0;
}

int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet) return -1;

    /* Đổi EtherType: 0x88B5 → 0x0800 */
    if (g_fake_ethertype != 0) {
        packet[12] = (ETHERTYPE_IPV4 >> 8) & 0xFF;
        packet[13] = ETHERTYPE_IPV4 & 0xFF;
    }

    /* Build IV từ IP header */
    uint8_t iv[AES128_IV_SIZE];
    if (build_iv_from_packet(packet, pkt_len, iv) != 0) {
        return -1;
    }

    /* Lấy L4 payload */
    uint8_t *payload;
    size_t payload_len;
    if (get_payload_info(packet, pkt_len, &payload, &payload_len) != 0) {
        return -1;
    }

    /* Decrypt L4 payload */
    if (fast_aes_ctr(iv, payload, (int)payload_len) != 0) {
        return -1;
    }

    return 0;
}

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx) {
    if (ctx) {
        memset(ctx->round_key, 0, sizeof(ctx->round_key));
        memset(ctx->base_iv, 0, sizeof(ctx->base_iv));
        ctx->fake_ethertype = 0;
        ctx->initialized = false;
    }

    memset(g_key, 0, sizeof(g_key));
    memset(g_base_iv, 0, sizeof(g_base_iv));
    g_fake_ethertype = 0;
    g_initialized = 0;

    if (tls_ctx) {
        EVP_CIPHER_CTX_free(tls_ctx);
        tls_ctx = NULL;
        tls_cipher_ready = 0;
    }
}
