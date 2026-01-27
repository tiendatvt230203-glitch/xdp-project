/*
 * Packet Encryption Module - AES-128 CTR Mode
 *
 * Encrypts Layer 3/4/7 (IP header + TCP/UDP + Payload)
 * Preserves Layer 2 (Ethernet header - MAC addresses)
 *
 * Packet structure:
 * ┌──────────────────┬─────────────────────────────────────┐
 * │ Ethernet (14B)   │ IP + TCP/UDP + Payload              │
 * │ NOT ENCRYPTED    │ ENCRYPTED (AES-128 CTR)             │
 * └──────────────────┴─────────────────────────────────────┘
 *
 * Optimizations:
 * - Pre-computed round keys (one-time init)
 * - 64-bit XOR operations for speed
 * - Zero-copy in-place encryption
 * - No padding required (CTR mode)
 *
 * Complexity: O(n) where n = packet size
 * Memory: O(1) - stack only, no heap allocation
 */

#ifndef PACKET_CRYPTO_H
#define PACKET_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* AES-128 parameters */
#define AES128_KEY_SIZE       16
#define AES128_BLOCK_SIZE     16
#define AES128_IV_SIZE        16
#define AES128_ROUND_KEY_SIZE 256  /* OpenSSL AES_KEY needs ~244 bytes */

/* Ethernet header size - NOT encrypted */
#define ETH_HEADER_SIZE       14

/* Nonce size for IV derivation (prepended to encrypted area) */
#define CRYPTO_NONCE_SIZE     8

/*
 * Crypto context - one per thread for thread-safety
 */
struct packet_crypto_ctx {
    uint8_t round_key[AES128_ROUND_KEY_SIZE];  /* Pre-expanded AES key */
    uint8_t base_iv[AES128_IV_SIZE];           /* Base IV */
    uint64_t counter;                           /* Packet counter for unique IV */
    bool initialized;
};

/*
 * Initialize crypto context
 *
 * @param ctx      Context to initialize
 * @param key      16-byte AES-128 key
 * @param base_iv  16-byte base IV (NULL = use zeros)
 * @return         0 success, -1 error
 */
int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t key[AES128_KEY_SIZE],
                       const uint8_t base_iv[AES128_IV_SIZE]);

/*
 * Encrypt packet in-place (Layer 3/4/7 only)
 *
 * Before: [Eth Header 14B][IP Header][TCP/UDP][Payload]
 * After:  [Eth Header 14B][Nonce 8B][Encrypted IP+TCP+Payload]
 *
 * @param ctx       Initialized context
 * @param packet    Full packet starting from Ethernet header
 * @param pkt_len   Total packet length (must be > ETH_HEADER_SIZE)
 * @return          New packet length (original + CRYPTO_NONCE_SIZE), -1 on error
 *
 * Note: Buffer must have space for additional 8 bytes (nonce)
 */
int packet_encrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len);

/*
 * Decrypt packet in-place (Layer 3/4/7 only)
 *
 * Before: [Eth Header 14B][Nonce 8B][Encrypted data]
 * After:  [Eth Header 14B][IP Header][TCP/UDP][Payload]
 *
 * @param ctx       Initialized context
 * @param packet    Full packet starting from Ethernet header
 * @param pkt_len   Total packet length
 * @return          Original packet length (without nonce), -1 on error
 */
int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len);

/*
 * Encrypt raw buffer (no Ethernet header handling)
 * Used when you've already extracted the payload
 *
 * @param ctx       Initialized context
 * @param data      Data to encrypt in-place
 * @param len       Data length
 * @param nonce_out 8-byte nonce output
 * @return          0 success, -1 error
 */
int crypto_encrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          uint8_t nonce_out[CRYPTO_NONCE_SIZE]);

/*
 * Decrypt raw buffer
 *
 * @param ctx    Initialized context
 * @param data   Data to decrypt in-place
 * @param len    Data length
 * @param nonce  8-byte nonce from encryption
 * @return       0 success, -1 error
 */
int crypto_decrypt_buffer(struct packet_crypto_ctx *ctx,
                          uint8_t *data,
                          size_t len,
                          const uint8_t nonce[CRYPTO_NONCE_SIZE]);

/*
 * Cleanup - zeros sensitive data
 */
void packet_crypto_cleanup(struct packet_crypto_ctx *ctx);

#endif /* PACKET_CRYPTO_H */
