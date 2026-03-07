#ifndef CRYPTO_LAYER4_H
#define CRYPTO_LAYER4_H

#include "packet_crypto.h"

int crypto_layer4_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer4_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

#endif
