/*
 * Packet Encryption Implementation - AES-128 CTR Mode
 * Using OpenSSL AES-NI Hardware Acceleration
 *
 * OPTIMIZED: Key expanded once, reused for all packets
 * Expected: 3-10+ Gbps with AES-NI
 */

#include "packet_crypto.h"
#include <string.h>
#include <openssl/aes.h>

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES128_KEY_SIZE],
                       const uint8_t base_iv[AES128_IV_SIZE])
{
    if (!ctx || !key) return -1;

    /* Expand AES key ONCE (uses AES-NI if available) */
    AES_KEY aes_key;
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        return -1;
    }

    /* Store expanded key */
    memcpy(ctx->round_key, &aes_key, sizeof(AES_KEY));

    /* Set base IV */
    if (base_iv) {
        memcpy(ctx->base_iv, base_iv, AES128_IV_SIZE);
    } else {
        memset(ctx->base_iv, 0, AES128_IV_SIZE);
    }

    ctx->counter = 0;
    ctx->initialized = true;

    return 0;
}

/* Build IV: [base_iv 8 bytes][nonce 8 bytes] */
static inline void build_iv(const struct packet_crypto_ctx *ctx,
                            const uint8_t nonce[CRYPTO_NONCE_SIZE],
                            uint8_t iv_out[AES128_IV_SIZE])
{
    *(uint64_t *)iv_out = *(const uint64_t *)ctx->base_iv;
    *(uint64_t *)(iv_out + 8) = *(const uint64_t *)nonce;
}

/* Increment 128-bit counter */
static inline void increment_iv(uint8_t iv[AES128_IV_SIZE])
{
    for (int i = AES128_IV_SIZE - 1; i >= 0; i--) {
        if (++iv[i] != 0) break;
    }
}

/*
 * AES-128 CTR with 64-bit XOR optimization
 * AES_encrypt uses AES-NI automatically on supported CPUs
 */
static void aes_ctr_xcrypt(const AES_KEY *key,
                           uint8_t *iv,
                           uint8_t *data,
                           size_t len)
{
    uint8_t keystream[AES128_BLOCK_SIZE];
    size_t offset = 0;

    while (offset < len) {
        /* Generate keystream block (AES-NI accelerated) */
        AES_encrypt(iv, keystream, key);

        size_t remaining = len - offset;

        if (remaining >= AES128_BLOCK_SIZE) {
            /* Full block: 64-bit XOR */
            uint64_t *d = (uint64_t *)(data + offset);
            uint64_t *k = (uint64_t *)keystream;
            d[0] ^= k[0];
            d[1] ^= k[1];
            offset += AES128_BLOCK_SIZE;
        } else {
            /* Partial block */
            for (size_t i = 0; i < remaining; i++) {
                data[offset + i] ^= keystream[i];
            }
            offset += remaining;
        }

        increment_iv(iv);
    }
}

int crypto_encrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          uint8_t nonce_out[CRYPTO_NONCE_SIZE])
{
    if (!ctx || !ctx->initialized || !data || len == 0) return -1;

    uint64_t nonce_val = __sync_fetch_and_add(&ctx->counter, 1);
    *(uint64_t *)nonce_out = nonce_val;

    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce_out, iv);

    aes_ctr_xcrypt((const AES_KEY *)ctx->round_key, iv, data, len);

    return 0;
}

int crypto_decrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          const uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    if (!ctx || !ctx->initialized || !data || len == 0 || !nonce) return -1;

    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce, iv);

    aes_ctr_xcrypt((const AES_KEY *)ctx->round_key, iv, data, len);

    return 0;
}

int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len)
{
    if (!ctx || !ctx->initialized || !packet) return -1;
    if (pkt_len <= ETH_HEADER_SIZE) return -1;

    uint8_t *payload = packet + ETH_HEADER_SIZE;
    size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    uint64_t nonce_val = __sync_fetch_and_add(&ctx->counter, 1);
    *(uint64_t *)nonce = nonce_val;

    memmove(payload + CRYPTO_NONCE_SIZE, payload, payload_len);
    memcpy(payload, nonce, CRYPTO_NONCE_SIZE);

    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce, iv);
    aes_ctr_xcrypt((const AES_KEY *)ctx->round_key, iv,
                   payload + CRYPTO_NONCE_SIZE, payload_len);

    return (int)(pkt_len + CRYPTO_NONCE_SIZE);
}

int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len)
{
    if (!ctx || !ctx->initialized || !packet) return -1;
    if (pkt_len <= ETH_HEADER_SIZE + CRYPTO_NONCE_SIZE) return -1;

    uint8_t *nonce = packet + ETH_HEADER_SIZE;
    uint8_t *encrypted = nonce + CRYPTO_NONCE_SIZE;
    size_t encrypted_len = pkt_len - ETH_HEADER_SIZE - CRYPTO_NONCE_SIZE;

    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce, iv);
    aes_ctr_xcrypt((const AES_KEY *)ctx->round_key, iv, encrypted, encrypted_len);

    memmove(packet + ETH_HEADER_SIZE, encrypted, encrypted_len);

    return (int)(pkt_len - CRYPTO_NONCE_SIZE);
}

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx)
{
    if (ctx) {
        memset(ctx->round_key, 0, sizeof(ctx->round_key));
        memset(ctx->base_iv, 0, sizeof(ctx->base_iv));
        ctx->counter = 0;
        ctx->initialized = false;
    }
}
