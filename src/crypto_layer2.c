#include "../inc/crypto_layer2.h"
#include <string.h>
#include <openssl/evp.h>

/* ========================================================================
 * ULTRA FAST LAYER 2: KHÔNG CHECK GÌ HẾT
 * - 1 key cố định
 * - Không verify tag
 * - Nhận → mã hóa/giải mã → forward
 * ======================================================================== */

/* Thread-local */
static __thread uint32_t tls_counter = 0;
static __thread EVP_CIPHER_CTX *tls_enc_ctx = NULL;
static __thread EVP_CIPHER_CTX *tls_dec_ctx = NULL;
static __thread int tls_ctx_init = 0;

/* Global cached */
static int g_nonce_size = 12;
static int g_enc_start = 25;
static uint8_t g_marker = 0;
static uint8_t g_key[32];
static int g_key_size = 16;

void crypto_layer2_fast_init(struct packet_crypto_ctx *ctx, int nonce_size, uint16_t fake_etype) {
    g_nonce_size = nonce_size;
    g_enc_start = 13 + nonce_size;
    g_marker = (uint8_t)(fake_etype >> 8);
    g_key_size = (packet_crypto_get_aes_bits() == 256) ? 32 : 16;
    memcpy(g_key, ctx->keys[KEY_SLOT_CURRENT], g_key_size);
}

static inline void init_thread_ctx(void) {
    if (tls_ctx_init) return;
    
    const EVP_CIPHER *cipher = (g_key_size == 32) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    
    tls_enc_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(tls_enc_ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(tls_enc_ctx, EVP_CTRL_GCM_SET_IVLEN, g_nonce_size, NULL);
    EVP_EncryptInit_ex(tls_enc_ctx, NULL, NULL, g_key, NULL);
    
    tls_dec_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(tls_dec_ctx, cipher, NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(tls_dec_ctx, EVP_CTRL_GCM_SET_IVLEN, g_nonce_size, NULL);
    EVP_DecryptInit_ex(tls_dec_ctx, NULL, NULL, g_key, NULL);
    
    tls_ctx_init = 1;
}

/* ENCRYPT: Nhận → mã hóa → done */
int crypto_layer2_encrypt_fast(struct packet_crypto_ctx *ctx, uint8_t *pkt, size_t len) {
    (void)ctx;
    init_thread_ctx();
    
    const size_t payload = len - 14;
    
    /* Nonce = counter */
    uint8_t nonce[16] = {0};
    uint32_t c = tls_counter++;
    nonce[0] = c >> 24; nonce[1] = c >> 16; nonce[2] = c >> 8; nonce[3] = c;
    
    /* Move + write header */
    memmove(pkt + g_enc_start, pkt + 14, payload);
    pkt[12] = g_marker;
    memcpy(pkt + 13, nonce, g_nonce_size);
    
    /* Encrypt */
    int outl;
    EVP_EncryptInit_ex(tls_enc_ctx, NULL, NULL, NULL, nonce);
    EVP_EncryptUpdate(tls_enc_ctx, pkt + g_enc_start, &outl, pkt + g_enc_start, (int)payload);
    EVP_EncryptFinal_ex(tls_enc_ctx, pkt + g_enc_start + outl, &outl);
    
    /* Tag */
    EVP_CIPHER_CTX_ctrl(tls_enc_ctx, EVP_CTRL_GCM_GET_TAG, 16, pkt + g_enc_start + payload);
    
    return (int)(len + g_nonce_size - 1 + 16);
}

/* DECRYPT: Nhận → giải mã → done. KHÔNG CHECK TAG */
int crypto_layer2_decrypt_fast(struct packet_crypto_ctx *ctx, uint8_t *pkt, size_t len) {
    (void)ctx;
    init_thread_ctx();
    
    const size_t enc_len = len - g_enc_start - 16;
    
    /* Nonce từ packet */
    uint8_t nonce[16] = {0};
    memcpy(nonce, pkt + 13, g_nonce_size);
    
    /* Decrypt - KHÔNG verify tag */
    int outl;
    EVP_DecryptInit_ex(tls_dec_ctx, NULL, NULL, NULL, nonce);
    EVP_DecryptUpdate(tls_dec_ctx, pkt + g_enc_start, &outl, pkt + g_enc_start, (int)enc_len);
    
    /* Restore ethertype + move */
    uint8_t *d = pkt + g_enc_start;
    pkt[12] = d[0];
    pkt[13] = d[1];
    memmove(pkt + 14, d + 2, enc_len - 2);
    
    return (int)(14 + enc_len - 2);
}
