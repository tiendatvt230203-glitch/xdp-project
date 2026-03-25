#include "../inc/crypto_dispatch.h"

#include "../inc/crypto_policy_utils.h"
#include "../inc/crypto_layer4.h"

#include <string.h>
#include <unistd.h>

#define L4_TUNNEL_MAGIC    0xA5

int crypto_l3_extract_policy_id(uint8_t *pkt, uint32_t pkt_len, uint8_t *policy_id_out) {
    if (!pkt || !policy_id_out || pkt_len < 14 + 20)
        return -1;

    uint16_t ether_type = ((uint16_t)pkt[12] << 8) | pkt[13];
    int l3_off;
    int ip_hdr_len;
    uint8_t proto;
    uint8_t marker = 99;
    int nonce_size = packet_crypto_get_nonce_size();

    if (ether_type == 0x0800) {
        l3_off = 14;
        ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
        if (ip_hdr_len < 20 || pkt_len < (uint32_t)(l3_off + ip_hdr_len + 1))
            return -1;
        proto = pkt[l3_off + 9];
    } else if (ether_type == 0x86DD) {
        l3_off = 14;
        ip_hdr_len = 40;
        if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + 1))
            return -1;
        proto = pkt[l3_off + 6];
    } else {
        return -1;
    }

    if (proto != marker)
        return -1;

    int tunnel_off = l3_off + ip_hdr_len;
    if (tunnel_off + nonce_size >= (int)pkt_len)
        return -1;

    *policy_id_out = (uint8_t)(pkt[tunnel_off + nonce_size] & 0x7F);
    return 0;
}

int crypto_l4_extract_policy_id_ipv4(uint8_t *pkt,
                                      uint32_t pkt_len,
                                      uint8_t *policy_id_out,
                                      int *nonce_size_out) {
    if (!pkt || !policy_id_out || !nonce_size_out)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + 20))
        return -1;

    uint8_t ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    if (pkt_len < (uint32_t)(l3_off + ip_hdr_len + 8))
        return -1;

    uint8_t ip_proto = pkt[l3_off + 9];
    int transport_off = l3_off + ip_hdr_len;
    int candidates[4] = {4, 8, 12, 16};

    if (ip_proto == 6) {
        if (pkt_len < (uint32_t)(transport_off + 20))
            return -1;
        uint8_t tcp_hdr_len = ((pkt[transport_off + 12] >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20)
            return -1;
        int legacy_tun = transport_off + tcp_hdr_len;

        for (int i = 0; i < 4; i++) {
            int ns = candidates[i];
            /* Full-segment L4 TCP tunnel immediately after IP */
            if (transport_off + ns + 1 < (int)pkt_len &&
                pkt[transport_off + ns + 1] == L4_TUNNEL_MAGIC) {
                *nonce_size_out = ns;
                *policy_id_out = (uint8_t)(pkt[transport_off + ns] & 0x7F);
                return 0;
            }
            /* Legacy tunnel after TCP header */
            if (legacy_tun + ns + 1 < (int)pkt_len &&
                pkt[legacy_tun + ns + 1] == L4_TUNNEL_MAGIC) {
                *nonce_size_out = ns;
                *policy_id_out = (uint8_t)(pkt[legacy_tun + ns] & 0x7F);
                return 0;
            }
        }
        return -1;
    }

    if (ip_proto == 17) {
        int tunnel_off = transport_off + 8;
        if (tunnel_off >= (int)pkt_len)
            return -1;
        for (int i = 0; i < 4; i++) {
            int ns = candidates[i];
            if (tunnel_off + ns + 1 >= (int)pkt_len)
                continue;
            if (pkt[tunnel_off + ns + 1] == L4_TUNNEL_MAGIC) {
                *nonce_size_out = ns;
                *policy_id_out = (uint8_t)(pkt[tunnel_off + ns] & 0x7F);
                return 0;
            }
        }
    }

    return -1;
}

int crypto_decrypt_packet_auto_by_action(
    int crypto_enabled,
    struct app_config *cfg,
    struct crypto_dispatch_ctx *dctx,
    int action_layer,
    uint8_t *pkt, uint32_t *pkt_len,
    uint8_t *scratch, size_t scratch_sz) {

    if (!crypto_enabled || !cfg || !dctx || !dctx->base_ctx || !pkt || !pkt_len)
        return -1;

    if (cfg->policy_count <= 0) {
        crypto_apply_default_from_cfg(cfg);
        int new_len = packet_decrypt(dctx->base_ctx, pkt, *pkt_len);
        if (new_len < 0) return -1;
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    if (action_layer == POLICY_ACTION_ENCRYPT_L3) {
        uint8_t policy_id = 0;
        if (crypto_l3_extract_policy_id(pkt, *pkt_len, &policy_id) != 0)
            return 0;

        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &cfg->policies[pi];
            if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L3)
                continue;
            if (!dctx->per_policy_ready || !dctx->per_policy_ready[pi])
                continue;
            if ((uint8_t)(cp->id & 0x7F) != policy_id)
                continue;

            crypto_apply_from_policy(cp);
            int new_len = packet_decrypt(&dctx->per_policy_ctx[pi], pkt, *pkt_len);
            if (new_len < 0)
                return -1;
            *pkt_len = (uint32_t)new_len;
            return 0;
        }
        return -1;
    }

    if (action_layer == POLICY_ACTION_ENCRYPT_L4) {
        int l3_off = crypto_eth_ipv4_offset(pkt, *pkt_len);
        if (l3_off < 0)
            return 0;

        uint8_t ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
        if (ip_hdr_len < 20)
            return 0;
        if (*pkt_len < (uint32_t)(l3_off + ip_hdr_len + 8))
            return 0;

        uint8_t ip_proto = pkt[l3_off + 9];
        if (ip_proto != 6 && ip_proto != 17)
            return 0;

        int transport_off = l3_off + ip_hdr_len;

        int tcp_hdr_len = 0;
        if (ip_proto == 6) {
            if (*pkt_len < (uint32_t)(transport_off + 20))
                return 0;
            tcp_hdr_len = ((pkt[transport_off + 12] >> 4) & 0x0F) * 4;
            if (tcp_hdr_len < 20)
                return 0;
        }

        /* Strict match: only decrypt when magic + policy_id match. */
        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &cfg->policies[pi];
            if (!cp || cp->action != POLICY_ACTION_ENCRYPT_L4)
                continue;
            if (!dctx->per_policy_ready || !dctx->per_policy_ready[pi] || cp->nonce_size <= 0)
                continue;

            int ns = cp->nonce_size;
            int tunnel_off = -1;

            if (ip_proto == 6) {
                int off_new = transport_off;
                if (off_new + ns + 1 < (int)*pkt_len &&
                    pkt[off_new + ns + 1] == L4_TUNNEL_MAGIC &&
                    ((uint8_t)(pkt[off_new + ns] & 0x7F) == (uint8_t)(cp->id & 0x7F)) &&
                    ((pkt[off_new] & 0x80) == 0)) {
                    tunnel_off = off_new;
                } else {
                    int off_legacy = transport_off + tcp_hdr_len;
                    if (off_legacy + ns + 1 < (int)*pkt_len &&
                        pkt[off_legacy + ns + 1] == L4_TUNNEL_MAGIC &&
                        ((uint8_t)(pkt[off_legacy + ns] & 0x7F) == (uint8_t)(cp->id & 0x7F)) &&
                        ((pkt[off_legacy] & 0x80) == 0)) {
                        tunnel_off = off_legacy;
                    }
                }
            } else {
                int off_udp = transport_off + 8;
                if (off_udp + ns + 1 < (int)*pkt_len &&
                    pkt[off_udp + ns + 1] == L4_TUNNEL_MAGIC &&
                    ((uint8_t)(pkt[off_udp + ns] & 0x7F) == (uint8_t)(cp->id & 0x7F)) &&
                    ((pkt[off_udp] & 0x80) == 0)) {
                    tunnel_off = off_udp;
                }
            }

            if (tunnel_off < 0)
                continue;

            crypto_apply_from_policy(cp);
            int new_len = packet_decrypt(&dctx->per_policy_ctx[pi], pkt, *pkt_len);
            if (new_len < 0)
                return -1;
            *pkt_len = (uint32_t)new_len;
            return 0;
        }

        /* Not an L4-encrypted packet for any configured policy => pass. */
        return 0;
    }

    /* Fallback brute-force. */
    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp || cp->action != action_layer)
            continue;
        if (!dctx->per_policy_ready || !dctx->per_policy_ready[pi])
            continue;

        if (*pkt_len > scratch_sz)
            return -1;

        if (scratch)
            memcpy(scratch, pkt, *pkt_len);

        crypto_apply_from_policy(cp);
        int new_len = packet_decrypt(&dctx->per_policy_ctx[pi], pkt, *pkt_len);
        if (new_len < 0) {
            if (scratch)
                memcpy(pkt, scratch, *pkt_len);
            continue;
        }
        *pkt_len = (uint32_t)new_len;
        return 0;
    }

    return -1;
}

