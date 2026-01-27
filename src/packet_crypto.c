/*
 * Packet Encryption - AES-128 CTR Mode
 * OpenSSL 3.0 EVP Interface (AES-NI accelerated)
 *
 * Optimized: Single EVP context, reuse for all packets
 */

#include "packet_crypto.h"
#include <string.h>
#include <openssl/evp.h>

/* Thread-local EVP context for performance */
static __thread EVP_CIPHER_CTX *tls_ctx = NULL;
static __thread int tls_initialized = 0;

/* Get or create thread-local EVP context */
static EVP_CIPHER_CTX *get_evp_ctx(void)
{
    if (!tls_initialized) {
        tls_ctx = EVP_CIPHER_CTX_new();
        tls_initialized = 1;
    }
    return tls_ctx;
}

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES128_KEY_SIZE],
                       const uint8_t base_iv[AES128_IV_SIZE])
{
    if (!ctx || !key) return -1;

    memcpy(ctx->round_key, key, AES128_KEY_SIZE);

    if (base_iv) {
        memcpy(ctx->base_iv, base_iv, AES128_IV_SIZE);
    } else {
        memset(ctx->base_iv, 0, AES128_IV_SIZE);
    }

    ctx->counter = 0;
    ctx->initialized = true;

    /* Pre-initialize thread-local context */
    EVP_CIPHER_CTX *evp = get_evp_ctx();
    if (!evp) return -1;

    /* Initialize once with cipher, key - will change IV per packet */
    if (EVP_EncryptInit_ex(evp, EVP_aes_128_ctr(), NULL, key, ctx->base_iv) != 1) {
        return -1;
    }

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

/*
 * Fast AES-CTR using pre-initialized EVP context
 * Only changes IV per call, no cipher re-init
 */
static inline int fast_aes_ctr(const uint8_t *key,
                               const uint8_t *iv,
                               uint8_t *data,
                               int len)
{
    EVP_CIPHER_CTX *evp = get_evp_ctx();
    int out_len;

    /* Re-init with new IV only (cipher=NULL, key=NULL keeps existing) */
    if (EVP_EncryptInit_ex(evp, NULL, NULL, key, iv) != 1) {
        return -1;
    }

    /* Single-shot encrypt */
    if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) {
        return -1;
    }

    return 0;
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

    return fast_aes_ctr(ctx->round_key, iv, data, (int)len);
}

int crypto_decrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          const uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    if (!ctx || !ctx->initialized || !data || len == 0 || !nonce) return -1;

    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce, iv);

    return fast_aes_ctr(ctx->round_key, iv, data, (int)len);
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

    if (fast_aes_ctr(ctx->round_key, iv,
                     payload + CRYPTO_NONCE_SIZE, (int)payload_len) != 0) {
        return -1;
    }

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

    if (fast_aes_ctr(ctx->round_key, iv, encrypted, (int)encrypted_len) != 0) {
        return -1;
    }

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

    if (tls_ctx) {
        EVP_CIPHER_CTX_free(tls_ctx);
        tls_ctx = NULL;
        tls_initialized = 0;
    }
}
