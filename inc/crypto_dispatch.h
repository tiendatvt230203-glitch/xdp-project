#ifndef CRYPTO_DISPATCH_H
#define CRYPTO_DISPATCH_H

#include <stdint.h>
#include <stddef.h>

#include "config.h"
#include "packet_crypto.h"


struct crypto_dispatch_ctx {
    struct packet_crypto_ctx *base_ctx;                
    struct packet_crypto_ctx *per_policy_ctx;           
    int *per_policy_ready;                             
};


int crypto_l3_extract_policy_id(uint8_t *pkt, uint32_t pkt_len, uint8_t *policy_id_out);


int crypto_l4_extract_policy_id_ipv4(uint8_t *pkt,
                                      uint32_t pkt_len,
                                      uint8_t *policy_id_out,
                                      int *nonce_size_out);


int crypto_decrypt_packet_auto_by_action(
    int crypto_enabled,
    struct app_config *cfg,
    struct crypto_dispatch_ctx *dctx,
    int action_layer,
    uint8_t *pkt, uint32_t *pkt_len,
    uint8_t *scratch, size_t scratch_sz);

#endif 

