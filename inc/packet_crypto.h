#ifndef PACKET_CRYPTO_H
#define PACKET_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define AES128_KEY_SIZE       16
#define AES128_BLOCK_SIZE     16
#define AES128_IV_SIZE        16
#define AES128_ROUND_KEY_SIZE 256

#define ETH_HEADER_SIZE       14
#define ETHERTYPE_IPV4        0x0800

struct packet_crypto_ctx {
    uint8_t round_key[AES128_ROUND_KEY_SIZE];
    uint8_t base_iv[AES128_IV_SIZE];
    uint16_t fake_ethertype;  /* Fake EtherType (0x88B5) - quy ước giữa 2 server */
    bool initialized;
};

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES128_KEY_SIZE],
                       const uint8_t base_iv[AES128_IV_SIZE]);

/**
 * Set fake EtherType (2 server quy ước sẵn)
 * Encrypt: 0x0800 → fake_ethertype (0x88B5)
 * Decrypt: fake_ethertype → 0x0800
 */
void packet_crypto_set_fake_ethertype(struct packet_crypto_ctx *ctx,
                                      uint16_t fake_ethertype);

/**
 * Encrypt packet (IPv4 only, zero overhead)
 * - Implicit nonce từ IP header
 * - Chỉ encrypt L4 payload
 * - Đổi EtherType 0x0800 → fake
 */
int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len);

/**
 * Decrypt packet (IPv4 only, zero overhead)
 * - Đổi EtherType fake → 0x0800
 * - Decrypt L4 payload
 */
int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len);

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx);

#endif
