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
#define CRYPTO_NONCE_SIZE     8
#define DEFAULT_FAKE_ETHERTYPE  0x88B5
#define ORIG_ETHERTYPE_SIZE   2

struct packet_crypto_ctx {
    uint8_t round_key[AES128_ROUND_KEY_SIZE];
    uint8_t base_iv[AES128_IV_SIZE];
    uint64_t counter;
    bool initialized;
};

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES128_KEY_SIZE],
                       const uint8_t base_iv[AES128_IV_SIZE]);

int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len);

int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len);

int crypto_encrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          uint8_t nonce_out[CRYPTO_NONCE_SIZE]);

int crypto_decrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          const uint8_t nonce[CRYPTO_NONCE_SIZE]);

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx);
void packet_crypto_set_fake_ethertype(uint16_t fake_type);

#endif
