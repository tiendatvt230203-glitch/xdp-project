#ifndef CRYPTO_LAYER2_H
#define CRYPTO_LAYER2_H

#include "packet_crypto.h"

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

/* ULTRA FAST - 1 key, không check gì */
void crypto_layer2_fast_init(struct packet_crypto_ctx *ctx, int nonce_size, uint16_t fake_etype);
int crypto_layer2_encrypt_fast(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer2_decrypt_fast(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

#endif