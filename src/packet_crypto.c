/*
 * Packet Encryption Implementation - AES-128 CTR Mode
 *
 * Optimized for high-throughput network packet processing.
 * Encrypts everything after Ethernet header (Layer 3/4/7).
 */

#include "packet_crypto.h"
#include <string.h>
#include <arpa/inet.h>

/* ========== AES-128 Core Implementation (Optimized from tiny-AES-c) ========== */

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

#define Nb 4
#define Nk 4
#define Nr 10

typedef uint8_t state_t[4][4];

/* Key expansion - run once at init */
static void key_expansion(uint8_t *round_key, const uint8_t *key)
{
    uint8_t tempa[4];
    unsigned i, k;

    /* First round key is the key itself */
    for (i = 0; i < Nk; ++i) {
        round_key[(i * 4) + 0] = key[(i * 4) + 0];
        round_key[(i * 4) + 1] = key[(i * 4) + 1];
        round_key[(i * 4) + 2] = key[(i * 4) + 2];
        round_key[(i * 4) + 3] = key[(i * 4) + 3];
    }

    /* Derive remaining round keys */
    for (i = Nk; i < Nb * (Nr + 1); ++i) {
        k = (i - 1) * 4;
        tempa[0] = round_key[k + 0];
        tempa[1] = round_key[k + 1];
        tempa[2] = round_key[k + 2];
        tempa[3] = round_key[k + 3];

        if (i % Nk == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t u8tmp = tempa[0];
            tempa[0] = sbox[tempa[1]] ^ rcon[i / Nk];
            tempa[1] = sbox[tempa[2]];
            tempa[2] = sbox[tempa[3]];
            tempa[3] = sbox[u8tmp];
        }

        k = (i - Nk) * 4;
        round_key[i * 4 + 0] = round_key[k + 0] ^ tempa[0];
        round_key[i * 4 + 1] = round_key[k + 1] ^ tempa[1];
        round_key[i * 4 + 2] = round_key[k + 2] ^ tempa[2];
        round_key[i * 4 + 3] = round_key[k + 3] ^ tempa[3];
    }
}

static inline void add_round_key(uint8_t round, state_t *state, const uint8_t *round_key)
{
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            (*state)[i][j] ^= round_key[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

static inline void sub_bytes(state_t *state)
{
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            (*state)[j][i] = sbox[(*state)[j][i]];
        }
    }
}

static inline void shift_rows(state_t *state)
{
    uint8_t temp;

    /* Row 1: shift left by 1 */
    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    /* Row 2: shift left by 2 */
    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    /* Row 3: shift left by 3 */
    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static inline uint8_t xtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static inline void mix_columns(state_t *state)
{
    uint8_t tmp, tm, t;
    for (int i = 0; i < 4; ++i) {
        t = (*state)[i][0];
        tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        tm = (*state)[i][0] ^ (*state)[i][1]; tm = xtime(tm); (*state)[i][0] ^= tm ^ tmp;
        tm = (*state)[i][1] ^ (*state)[i][2]; tm = xtime(tm); (*state)[i][1] ^= tm ^ tmp;
        tm = (*state)[i][2] ^ (*state)[i][3]; tm = xtime(tm); (*state)[i][2] ^= tm ^ tmp;
        tm = (*state)[i][3] ^ t;              tm = xtime(tm); (*state)[i][3] ^= tm ^ tmp;
    }
}

/* AES-128 block cipher (encrypt one 16-byte block) */
static void aes_cipher_block(state_t *state, const uint8_t *round_key)
{
    add_round_key(0, state, round_key);

    for (uint8_t round = 1; round < Nr; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(round, state, round_key);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(Nr, state, round_key);
}

/* ========== CTR Mode Optimized Implementation ========== */

/*
 * CTR mode XOR with 64-bit operations for speed
 * Processes 16 bytes at a time, handles remainder
 */
static void ctr_xcrypt_optimized(const uint8_t *round_key,
                                  uint8_t *iv,
                                  uint8_t *data,
                                  size_t len)
{
    uint8_t keystream[AES128_BLOCK_SIZE];
    size_t offset = 0;

    while (offset < len) {
        /* Generate keystream block from IV */
        memcpy(keystream, iv, AES128_BLOCK_SIZE);
        aes_cipher_block((state_t *)keystream, round_key);

        /* XOR data with keystream */
        size_t block_len = (len - offset < AES128_BLOCK_SIZE) ? (len - offset) : AES128_BLOCK_SIZE;

        /* Optimized: process 8 bytes at a time if possible */
        if (block_len == AES128_BLOCK_SIZE) {
            uint64_t *data64 = (uint64_t *)(data + offset);
            uint64_t *ks64 = (uint64_t *)keystream;
            data64[0] ^= ks64[0];
            data64[1] ^= ks64[1];
        } else {
            /* Handle remainder bytes */
            for (size_t i = 0; i < block_len; ++i) {
                data[offset + i] ^= keystream[i];
            }
        }

        /* Increment IV (counter) - big-endian increment from end */
        for (int i = AES128_BLOCK_SIZE - 1; i >= 0; --i) {
            if (++iv[i] != 0) break;
        }

        offset += block_len;
    }
}

/* ========== Public API ========== */

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES128_KEY_SIZE],
                       const uint8_t base_iv[AES128_IV_SIZE])
{
    if (!ctx || !key) return -1;

    /* Expand key (pre-compute round keys) */
    key_expansion(ctx->round_key, key);

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

/*
 * Build IV from base_iv + nonce
 * IV structure: [base_iv first 8 bytes][nonce 8 bytes]
 */
static void build_iv(const struct packet_crypto_ctx *ctx,
                     const uint8_t nonce[CRYPTO_NONCE_SIZE],
                     uint8_t iv_out[AES128_IV_SIZE])
{
    memcpy(iv_out, ctx->base_iv, 8);
    memcpy(iv_out + 8, nonce, CRYPTO_NONCE_SIZE);
}

int crypto_encrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          uint8_t nonce_out[CRYPTO_NONCE_SIZE])
{
    if (!ctx || !ctx->initialized || !data || len == 0) return -1;

    /* Generate unique nonce from counter */
    uint64_t nonce_val = __sync_fetch_and_add(&ctx->counter, 1);
    memcpy(nonce_out, &nonce_val, CRYPTO_NONCE_SIZE);

    /* Build full IV */
    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce_out, iv);

    /* Encrypt with CTR mode */
    ctr_xcrypt_optimized(ctx->round_key, iv, data, len);

    return 0;
}

int crypto_decrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          const uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    if (!ctx || !ctx->initialized || !data || len == 0 || !nonce) return -1;

    /* Build full IV from nonce */
    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce, iv);

    /* Decrypt with CTR mode (same as encrypt) */
    ctr_xcrypt_optimized(ctx->round_key, iv, data, len);

    return 0;
}

int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len)
{
    if (!ctx || !ctx->initialized || !packet) return -1;
    if (pkt_len <= ETH_HEADER_SIZE) return -1;

    /* Payload starts after Ethernet header */
    uint8_t *payload = packet + ETH_HEADER_SIZE;
    size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    /* Generate nonce */
    uint8_t nonce[CRYPTO_NONCE_SIZE];
    uint64_t nonce_val = __sync_fetch_and_add(&ctx->counter, 1);
    memcpy(nonce, &nonce_val, CRYPTO_NONCE_SIZE);

    /* Shift payload to make room for nonce */
    memmove(payload + CRYPTO_NONCE_SIZE, payload, payload_len);

    /* Insert nonce */
    memcpy(payload, nonce, CRYPTO_NONCE_SIZE);

    /* Build IV and encrypt */
    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce, iv);

    /* Encrypt payload (after nonce) */
    ctr_xcrypt_optimized(ctx->round_key, iv,
                         payload + CRYPTO_NONCE_SIZE, payload_len);

    return (int)(pkt_len + CRYPTO_NONCE_SIZE);
}

int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len)
{
    if (!ctx || !ctx->initialized || !packet) return -1;
    if (pkt_len <= ETH_HEADER_SIZE + CRYPTO_NONCE_SIZE) return -1;

    /* Extract nonce (right after Ethernet header) */
    uint8_t *nonce = packet + ETH_HEADER_SIZE;
    uint8_t *encrypted = nonce + CRYPTO_NONCE_SIZE;
    size_t encrypted_len = pkt_len - ETH_HEADER_SIZE - CRYPTO_NONCE_SIZE;

    /* Build IV and decrypt */
    uint8_t iv[AES128_IV_SIZE];
    build_iv(ctx, nonce, iv);

    ctr_xcrypt_optimized(ctx->round_key, iv, encrypted, encrypted_len);

    /* Shift decrypted data back (remove nonce space) */
    memmove(packet + ETH_HEADER_SIZE, encrypted, encrypted_len);

    return (int)(pkt_len - CRYPTO_NONCE_SIZE);
}

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx)
{
    if (ctx) {
        /* Zero sensitive data */
        memset(ctx->round_key, 0, sizeof(ctx->round_key));
        memset(ctx->base_iv, 0, sizeof(ctx->base_iv));
        ctx->counter = 0;
        ctx->initialized = false;
    }
}
