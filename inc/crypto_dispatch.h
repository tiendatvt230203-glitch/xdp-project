#ifndef CRYPTO_DISPATCH_H
#define CRYPTO_DISPATCH_H

#include <stdint.h>
#include <stddef.h>

#include "config.h"
#include "packet_crypto.h"

/* Dispatch context passed from forwarder (so module doesn't need to know globals). */
struct crypto_dispatch_ctx {
    struct packet_crypto_ctx *base_ctx;                 /* typically: &crypto_ctx */
    struct packet_crypto_ctx *per_policy_ctx;           /* array: g_policy_crypto_ctx[] */
    int *per_policy_ready;                             /* array: g_policy_crypto_ctx_ready[] */
};

/* Extract tunnel policy_id for L3 (fake ip-proto marker = 99). */
int crypto_l3_extract_policy_id(uint8_t *pkt, uint32_t pkt_len, uint8_t *policy_id_out);

/* Extract tunnel policy_id + nonce_size for L4 tunnel (IPv4 TCP/UDP). */
int crypto_l4_extract_policy_id_ipv4(uint8_t *pkt,
                                      uint32_t pkt_len,
                                      uint8_t *policy_id_out,
                                      int *nonce_size_out);

/* Decrypt/strip encrypted packet by a requested action layer.
 * Returns:
 *   0  => pass-through or successful decrypt
 *   -1 => fatal decrypt error (caller should drop)
 */
int crypto_decrypt_packet_auto_by_action(
    int crypto_enabled,
    struct app_config *cfg,
    struct crypto_dispatch_ctx *dctx,
    int action_layer,
    uint8_t *pkt, uint32_t *pkt_len,
    uint8_t *scratch, size_t scratch_sz);

#endif /* CRYPTO_DISPATCH_H */

