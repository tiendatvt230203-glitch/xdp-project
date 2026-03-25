#ifndef CRYPTO_POLICY_UTILS_H
#define CRYPTO_POLICY_UTILS_H

#include <stdint.h>
#include "config.h"

/* Apply default crypto parameters from global xdp_configs row. */
void crypto_apply_default_from_cfg(const struct app_config *cfg);

/* Apply per-policy crypto parameters (mode/aes/nonce + encrypt_layer override + fake_protocol + policy_id). */
void crypto_apply_from_policy(const struct crypto_policy *cp);

/* Select matching crypto policy for the given flow (uses profile + crypto policy tables loaded into cfg). */
const struct crypto_policy *crypto_select_policy_for_flow(const struct app_config *cfg,
                                                            uint32_t src_ip,
                                                            uint32_t dst_ip,
                                                            uint16_t src_port,
                                                            uint16_t dst_port,
                                                            uint8_t protocol);

#endif /* CRYPTO_POLICY_UTILS_H */

