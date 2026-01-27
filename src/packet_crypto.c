/*
 * Packet Encryption - AES-128 CTR Mode
 * OpenSSL 3.0 EVP Interface (AES-NI accelerated)
 *
 * FIXED: Thread-safe with proper per-thread initialization
 */

#include "packet_crypto.h"
#include <string.h>
#include <openssl/evp.h>

/* Shared key storage (set once at init, read by all threads) */
static uint8_t g_key[AES128_KEY_SIZE];
static uint8_t g_base_iv[AES128_IV_SIZE];
static volatile int g_initialized = 0;

/* Fake EtherType (configurable, 0 = disabled) */
static uint16_t g_fake_ethertype = DEFAULT_FAKE_ETHERTYPE;

/* Thread-local EVP context */
static __thread EVP_CIPHER_CTX *tls_ctx = NULL;
static __thread int tls_cipher_ready = 0;

/* Get or create thread-local EVP context with cipher initialized */
static EVP_CIPHER_CTX *get_ready_ctx(void)
{
    if (!tls_ctx) {
        tls_ctx = EVP_CIPHER_CTX_new();
        if (!tls_ctx) return NULL;
    }

    /* Initialize cipher if not done yet for this thread */
    if (!tls_cipher_ready) {
        if (EVP_EncryptInit_ex(tls_ctx, EVP_aes_128_ctr(), NULL, g_key, g_base_iv) != 1) {
            return NULL;
        }
        tls_cipher_ready = 1;
    }

    return tls_ctx;
}

void packet_crypto_set_fake_ethertype(uint16_t fake_type)
{
    g_fake_ethertype = fake_type;
}

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES128_KEY_SIZE],
                       const uint8_t base_iv[AES128_IV_SIZE])
{
    if (!ctx || !key) return -1;

    /* Store key globally for all threads */
    memcpy(g_key, key, AES128_KEY_SIZE);
    memcpy(ctx->round_key, key, AES128_KEY_SIZE);

    if (base_iv) {
        memcpy(g_base_iv, base_iv, AES128_IV_SIZE);
        memcpy(ctx->base_iv, base_iv, AES128_IV_SIZE);
    } else {
        memset(g_base_iv, 0, AES128_IV_SIZE);
        memset(ctx->base_iv, 0, AES128_IV_SIZE);
    }

    ctx->counter = 0;
    ctx->initialized = true;
    g_initialized = 1;

    /* Initialize this thread's context */
    if (!get_ready_ctx()) {
        return -1;
    }

    return 0;
}

/* Build IV: [base_iv 8 bytes][nonce 8 bytes] */
static inline void build_iv(const uint8_t nonce[CRYPTO_NONCE_SIZE],
                            uint8_t iv_out[AES128_IV_SIZE])
{
    memcpy(iv_out, g_base_iv, 8);
    memcpy(iv_out + 8, nonce, CRYPTO_NONCE_SIZE);
}

/*
 * Fast AES-CTR using thread-local EVP context
 */
static int fast_aes_ctr(const uint8_t *iv, uint8_t *data, int len)
{
    EVP_CIPHER_CTX *evp = get_ready_ctx();
    if (!evp) return -1;

    int out_len;

    /* Re-init with new IV (key stays the same) */
    if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, iv) != 1) {
        return -1;
    }

    /* Encrypt/decrypt */
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
    memcpy(nonce_out, &nonce_val, CRYPTO_NONCE_SIZE);

    uint8_t iv[AES128_IV_SIZE];
    build_iv(nonce_out, iv);

    return fast_aes_ctr(iv, data, (int)len);
}

int crypto_decrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          const uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    if (!ctx || !ctx->initialized || !data || len == 0 || !nonce) return -1;

    uint8_t iv[AES128_IV_SIZE];
    build_iv(nonce, iv);

    return fast_aes_ctr(iv, data, (int)len);
}

int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len)
{
    if (!ctx || !ctx->initialized || !packet) return -1;
    if (pkt_len <= ETH_HEADER_SIZE) return -1;

    uint8_t *payload = packet + ETH_HEADER_SIZE;
    size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    /* Save original EtherType (bytes 12-13) */
    uint8_t orig_ethertype[ORIG_ETHERTYPE_SIZE];
    orig_ethertype[0] = packet[12];
    orig_ethertype[1] = packet[13];

    /* Generate nonce */
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    uint64_t nonce_val = __sync_fetch_and_add(&ctx->counter, 1);
    memcpy(nonce, &nonce_val, CRYPTO_NONCE_SIZE);

    /* Shift payload to make room for nonce + orig_ethertype */
    size_t header_size = CRYPTO_NONCE_SIZE + ORIG_ETHERTYPE_SIZE;
    memmove(payload + header_size, payload, payload_len);

    /* Write nonce and original ethertype */
    memcpy(payload, nonce, CRYPTO_NONCE_SIZE);
    memcpy(payload + CRYPTO_NONCE_SIZE, orig_ethertype, ORIG_ETHERTYPE_SIZE);

    /* Build IV and encrypt (encrypt after nonce+orig_type) */
    uint8_t iv[AES128_IV_SIZE];
    build_iv(nonce, iv);

    if (fast_aes_ctr(iv, payload + header_size, (int)payload_len) != 0) {
        return -1;
    }

    /* Replace EtherType with fake value (if enabled) */
    if (g_fake_ethertype != 0) {
        packet[12] = (g_fake_ethertype >> 8) & 0xFF;  /* High byte */
        packet[13] = g_fake_ethertype & 0xFF;          /* Low byte */
    }

    return (int)(pkt_len + header_size);
}

int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len)
{
    if (!ctx || !ctx->initialized || !packet) return -1;

    size_t header_size = CRYPTO_NONCE_SIZE + ORIG_ETHERTYPE_SIZE;
    if (pkt_len <= ETH_HEADER_SIZE + header_size) return -1;

    uint8_t *nonce = packet + ETH_HEADER_SIZE;
    uint8_t *orig_ethertype = nonce + CRYPTO_NONCE_SIZE;
    uint8_t *encrypted = orig_ethertype + ORIG_ETHERTYPE_SIZE;
    size_t encrypted_len = pkt_len - ETH_HEADER_SIZE - header_size;

    /* Build IV and decrypt */
    uint8_t iv[AES128_IV_SIZE];
    build_iv(nonce, iv);

    if (fast_aes_ctr(iv, encrypted, (int)encrypted_len) != 0) {
        return -1;
    }

    /* Restore original EtherType */
    packet[12] = orig_ethertype[0];
    packet[13] = orig_ethertype[1];

    /* Remove nonce+orig_type space */
    memmove(packet + ETH_HEADER_SIZE, encrypted, encrypted_len);

    return (int)(pkt_len - header_size);
}

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx)
{
    if (ctx) {
        memset(ctx->round_key, 0, sizeof(ctx->round_key));
        memset(ctx->base_iv, 0, sizeof(ctx->base_iv));
        ctx->counter = 0;
        ctx->initialized = false;
    }

    /* Clear global key */
    memset(g_key, 0, sizeof(g_key));
    memset(g_base_iv, 0, sizeof(g_base_iv));
    g_initialized = 0;

    /* Note: thread-local contexts will be cleaned up when threads exit */
    if (tls_ctx) {
        EVP_CIPHER_CTX_free(tls_ctx);
        tls_ctx = NULL;
        tls_cipher_ready = 0;
    }
}
