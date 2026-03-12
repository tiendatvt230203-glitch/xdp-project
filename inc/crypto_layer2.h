#ifndef CRYPTO_LAYER2_H
#define CRYPTO_LAYER2_H

#include "packet_crypto.h"

/* ULTRA FAST LAYER 2 - 1 key, không check gì */
void crypto_layer2_fast_init(struct packet_crypto_ctx *ctx, int nonce_size, uint16_t fake_etype);
int crypto_layer2_encrypt_fast(struct packet_crypto_ctx *ctx, uint8_t *pkt, size_t len);
int crypto_layer2_decrypt_fast(struct packet_crypto_ctx *ctx, uint8_t *pkt, size_t len);

#endif
