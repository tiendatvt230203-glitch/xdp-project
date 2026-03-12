#include "../inc/crypto_layer2.h"
#include "../inc/config.h"
#include <string.h>
#include <stdio.h>

#define MIN_ETH_PKT  (ETH_HEADER_SIZE + 8)

/* Compiler hints for branch prediction */
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

/* ========================================================================
 * ULTRA FAST: KHÔNG CHECK GÌ HẾT
 * - 1 key cố định
 * - Không verify tag
 * - Nhận → mã hóa/giải mã → forward
 * ======================================================================== */

#include <openssl/evp.h>

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
    
    /* Decrypt - KHÔNG verify tag, chỉ decrypt */
    int outl;
    EVP_DecryptInit_ex(tls_dec_ctx, NULL, NULL, NULL, nonce);
    EVP_DecryptUpdate(tls_dec_ctx, pkt + g_enc_start, &outl, pkt + g_enc_start, (int)enc_len);
    /* SKIP: EVP_DecryptFinal_ex - không cần verify tag */
    
    /* Restore ethertype + move */
    uint8_t *d = pkt + g_enc_start;
    pkt[12] = d[0];
    pkt[13] = d[1];
    memmove(pkt + 14, d + 2, enc_len - 2);
    
    return (int)(14 + enc_len - 2);
}

/* Inline verify functions - chỉ dùng cho CTR mode */
static inline __attribute__((always_inline))
int verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len) {
    if (unlikely(len < 20)) return 0;
    uint8_t ttl   = ip_payload[8];
    uint8_t proto = ip_payload[9];
    if (unlikely(ttl == 0)) return 0;
    if (proto == 1 || proto == 2 || proto == 6 || proto == 17 ||
        proto == 47 || proto == 50 || proto == 51 || proto == 58 ||
        proto == 89 || proto == 132)
        return 1;
    return 0;
}

static inline __attribute__((always_inline))
int verify_ipv6_after_decrypt(const uint8_t *ip_payload, size_t len) {
    if (unlikely(len < 40)) return 0;
    uint8_t next_hdr  = ip_payload[6];
    uint8_t hop_limit = ip_payload[7];
    if (unlikely(hop_limit == 0)) return 0;
    if (next_hdr == 6 || next_hdr == 17 || next_hdr == 58 ||
        next_hdr == 44 || next_hdr == 43 || next_hdr == 0 || next_hdr == 60)
        return 1;
    return 0;
}

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (unlikely(!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT)) return -1;

    const int nonce_size = packet_crypto_get_nonce_size();
    const int l2_hdr_extra = nonce_size - 1;
    const int l2_enc_start = 13 + nonce_size;

    uint16_t ether_type = ((uint16_t)packet[12] << 8) | packet[13];
    uint8_t proto_flag;
    uint16_t fake_etype;

    if (likely(ether_type == 0x0800)) {
        proto_flag = PROTO_FLAG_IPV4;
        fake_etype = packet_crypto_get_fake_ethertype_ipv4();
    }
    else if (ether_type == 0x86DD) {
        proto_flag = PROTO_FLAG_IPV6;
        fake_etype = packet_crypto_get_fake_ethertype_ipv6();
    }
    else return (int)pkt_len;

    if (unlikely(fake_etype == 0)) return (int)pkt_len;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);

    crypto_generate_nonce(counter, proto_flag, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    const size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    /* OPTIMIZATION: Move payload trước, rồi encrypt tại chỗ mới.
     * Tránh encrypt rồi move (2 lần chạm memory) */
    memmove(packet + l2_enc_start, packet + ETH_HEADER_SIZE, payload_len);

    /* Ghi header (nonce + marker) vào khoảng trống vừa tạo */
    crypto_write_counter(packet, nonce, nonce_size, (uint8_t)(fake_etype >> 8));

    if (likely(is_gcm)) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (unlikely(crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                            packet + l2_enc_start, (int)payload_len, tag) != 0))
            return -1;
        memcpy(packet + l2_enc_start + payload_len, tag, AES128_GCM_TAG_SIZE);
        return (int)(pkt_len + l2_hdr_extra + AES128_GCM_TAG_SIZE);
    }
    else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (unlikely(crypto_aes_ctr_with_key(key, iv,
                                             packet + l2_enc_start, (int)payload_len) != 0))
            return -1;
        return (int)(pkt_len + l2_hdr_extra);
    }
}

int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (unlikely(!ctx || !ctx->initialized || !packet)) return -1;

    const int nonce_size = packet_crypto_get_nonce_size();
    const int l2_enc_start = 13 + nonce_size;

    if (unlikely(pkt_len < (size_t)l2_enc_start)) return -1;

    const uint16_t fake_ipv4 = packet_crypto_get_fake_ethertype_ipv4();
    const uint16_t fake_ipv6 = packet_crypto_get_fake_ethertype_ipv6();
    const uint8_t pkt_marker = packet[12];

    if (!((fake_ipv4 && pkt_marker == (uint8_t)(fake_ipv4 >> 8)) ||
          (fake_ipv6 && pkt_marker == (uint8_t)(fake_ipv6 >> 8)))) return (int)pkt_len;

    uint8_t proto_flag;
    uint8_t nonce[16];
    crypto_read_counter(packet, nonce_size, nonce, &proto_flag);
    const int is_ipv4 = (proto_flag == PROTO_FLAG_IPV4);
    const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);

    const int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    size_t enc_len = pkt_len - l2_enc_start;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    if (is_gcm) {
        if (unlikely(pkt_len < (size_t)(l2_enc_start + AES128_GCM_TAG_SIZE))) return -1;
        enc_len -= AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + l2_enc_start + enc_len, AES128_GCM_TAG_SIZE);
    }

    /* OPTIMIZATION: Dùng key hiện tại trước (99% trường hợp).
     * Chỉ thử key khác nếu thất bại (key rotation). */
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t *work_ptr = packet + l2_enc_start;

    if (likely(is_gcm)) {
        /* GCM mode: Tag đã đảm bảo integrity, không cần verify IP header */
        if (likely(crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) == 0)) {
            goto decrypt_success;
        }
        /* Fallback: thử key prev/next nếu current key thất bại (key rotation) */
        /* Cần backup vì decrypt đã modify data */
    }
    else {
        /* CTR mode */
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (likely(crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) == 0)) {
            if (likely(is_ipv4 ? verify_ipv4_after_decrypt(work_ptr, enc_len)
                               : verify_ipv6_after_decrypt(work_ptr, enc_len))) {
                goto decrypt_success;
            }
        }
    }
    /* Key hiện tại thất bại - drop packet (tránh loop 3 key tốn CPU) */
    return -1;

decrypt_success:
    /* Restore ethertype và move payload về vị trí chuẩn */
    {
        int has_ethertype = (work_ptr[0] == 0x08 && work_ptr[1] == 0x00) ||
                            (work_ptr[0] == 0x86 && work_ptr[1] == 0xDD);
        if (has_ethertype) {
            packet[12] = work_ptr[0];
            packet[13] = work_ptr[1];
            memmove(packet + ETH_HEADER_SIZE, work_ptr + 2, enc_len - 2);
            return (int)(ETH_HEADER_SIZE + enc_len - 2);
        } else {
            packet[12] = is_ipv4 ? 0x08 : 0x86;
            packet[13] = is_ipv4 ? 0x00 : 0xDD;
            memmove(packet + ETH_HEADER_SIZE, work_ptr, enc_len);
            return (int)(ETH_HEADER_SIZE + enc_len);
        }
    }
}
