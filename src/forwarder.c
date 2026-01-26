#include "../inc/forwarder.h"
#include <signal.h>
#include <poll.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

// ============== GLOBAL WINDOW LOAD BALANCING ==============
// Tất cả packets đi đều trên các WAN
// Cứ đủ 64KB thì đổi WAN (không quan tâm flow)

#define WINDOW_SIZE 65536  // 64KB per WAN

// ============== ENCRYPTION HOOKS (cho sau này) ==============

static int encrypt_packet(void *pkt_data, uint32_t *pkt_len)
{
    // TODO: Thêm mã hóa ở đây
    (void)pkt_data;
    (void)pkt_len;
    return 0;
}

static int decrypt_packet(void *pkt_data, uint32_t *pkt_len)
{
    // TODO: Thêm giải mã ở đây
    (void)pkt_data;
    (void)pkt_len;
    return 0;
}

// ============== FORWARDER ==============

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;

    // Initialize LOCAL interfaces (RX with XDP, TX for return traffic)
    for (int i = 0; i < cfg->local_count; i++) {
        if (interface_init_local(&fwd->locals[i], &cfg->locals[i], cfg->bpf_file) != 0) {
            fprintf(stderr, "Failed to init LOCAL %s\n", cfg->locals[i].ifname);
            goto err_locals;
        }
        fwd->local_count++;
    }

    // Initialize WAN interfaces (RX + TX combined with XDP)
    for (int i = 0; i < cfg->wan_count; i++) {
        if (interface_init_wan_rx(&fwd->wans[i], &cfg->wans[i], "bpf/xdp_wan_redirect.o") != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg->wans[i].ifname);
            goto err_wans;
        }
        fwd->wan_count++;
    }

    printf("\n[FWD] ══════════════════════════════════════════════════\n");
    printf("[FWD] Ready: %d LOCAL, %d WAN\n", fwd->local_count, fwd->wan_count);
    printf("[FWD] Load Balancer: Global window %dKB (đi đều trên WANs)\n", WINDOW_SIZE / 1024);
    printf("[FWD] ══════════════════════════════════════════════════\n\n");

    return 0;

err_wans:
    for (int j = 0; j < fwd->wan_count; j++)
        interface_cleanup(&fwd->wans[j]);
err_locals:
    for (int j = 0; j < fwd->local_count; j++)
        interface_cleanup(&fwd->locals[j]);
    return -1;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    for (int i = 0; i < fwd->local_count; i++)
        interface_cleanup(&fwd->locals[i]);

    for (int i = 0; i < fwd->wan_count; i++)
        interface_cleanup(&fwd->wans[i]);
}

// Get WAN using global window-based load balancing
// Packets đi đều trên các WAN - cứ 64KB thì đổi WAN
static struct xsk_interface *get_wan(struct forwarder *fwd, uint32_t pkt_len)
{
    // Cộng bytes vào window
    fwd->window_bytes += pkt_len;

    // Đủ 64KB → đổi WAN
    if (fwd->window_bytes >= WINDOW_SIZE) {
        fwd->current_wan = (fwd->current_wan + 1) % fwd->wan_count;
        fwd->window_bytes = 0;
    }

    return &fwd->wans[fwd->current_wan];
}

// Extract dest IP from packet
static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return 0;

    struct ether_header *eth = (struct ether_header *)pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    return ip->daddr;
}

void forwarder_run(struct forwarder *fwd)
{
    void *pkt_ptrs[BATCH_SIZE];
    uint32_t pkt_lens[BATCH_SIZE];
    uint64_t addrs[BATCH_SIZE];
    uint64_t last_stats = 0;
    uint64_t loop_count = 0;

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    printf("[FWD] Running... (Ctrl+C to stop)\n");
    printf("[FWD] ┌─────────────────────────────────────────────────────┐\n");
    printf("[FWD] │ LOCAL → WAN: global window load balancing          │\n");
    printf("[FWD] │              (packets đi đều trên tất cả WANs)      │\n");
    printf("[FWD] │ WAN → LOCAL: routed by dest IP                     │\n");
    printf("[FWD] │ Encryption: [HOOK READY]                           │\n");
    printf("[FWD] └─────────────────────────────────────────────────────┘\n\n");

    while (running) {
        loop_count++;

        // ===== Flow 1: LOCAL → WAN (outbound, global window load balanced) =====
        for (int local_idx = 0; local_idx < fwd->local_count; local_idx++) {
            struct xsk_interface *local = &fwd->locals[local_idx];

            int rcvd = interface_recv(local, pkt_ptrs, pkt_lens, addrs, BATCH_SIZE);
            if (rcvd > 0) {
                // Track which WANs need flushing
                int wan_used[MAX_INTERFACES] = {0};

                for (int i = 0; i < rcvd; i++) {
                    // HOOK: Encrypt before sending
                    if (encrypt_packet(pkt_ptrs[i], &pkt_lens[i]) != 0) {
                        fwd->total_dropped++;
                        continue;
                    }

                    // Get WAN (global window - đi đều trên các WAN)
                    struct xsk_interface *wan = get_wan(fwd, pkt_lens[i]);
                    int wan_idx = fwd->current_wan;

                    // Use batch TX (no kick yet)
                    if (interface_send_batch(wan, pkt_ptrs[i], pkt_lens[i]) == 0) {
                        fwd->local_to_wan++;
                        wan_used[wan_idx] = 1;
                    } else {
                        fwd->total_dropped++;
                    }
                }

                // Flush all WANs that were used
                for (int w = 0; w < fwd->wan_count; w++) {
                    if (wan_used[w])
                        interface_send_flush(&fwd->wans[w]);
                }

                interface_recv_release(local, addrs, rcvd);
            }
        }

        // ===== Flow 2: WAN → LOCAL (inbound, route by dest IP) =====
        for (int wan_idx = 0; wan_idx < fwd->wan_count; wan_idx++) {
            struct xsk_interface *wan = &fwd->wans[wan_idx];

            int rcvd = interface_recv(wan, pkt_ptrs, pkt_lens, addrs, BATCH_SIZE);
            if (rcvd > 0) {
                // Track which LOCALs need flushing
                int local_used[MAX_INTERFACES] = {0};

                for (int i = 0; i < rcvd; i++) {
                    // HOOK: Decrypt after receiving
                    if (decrypt_packet(pkt_ptrs[i], &pkt_lens[i]) != 0) {
                        fwd->total_dropped++;
                        continue;
                    }

                    // Get dest IP from packet
                    uint32_t dest_ip = get_dest_ip(pkt_ptrs[i], pkt_lens[i]);
                    if (dest_ip == 0) {
                        fwd->total_dropped++;
                        continue;
                    }

                    // Find LOCAL interface for this dest IP
                    int local_idx = config_find_local_for_ip(fwd->cfg, dest_ip);
                    if (local_idx < 0) {
                        fwd->total_dropped++;
                        continue;
                    }

                    // Forward to LOCAL using batch
                    struct xsk_interface *local = &fwd->locals[local_idx];
                    struct local_config *local_cfg = &fwd->cfg->locals[local_idx];

                    if (interface_send_to_local_batch(local, local_cfg, pkt_ptrs[i], pkt_lens[i]) == 0) {
                        fwd->wan_to_local++;
                        local_used[local_idx] = 1;
                    } else {
                        fwd->total_dropped++;
                    }
                }

                // Flush all LOCALs that were used
                for (int l = 0; l < fwd->local_count; l++) {
                    if (local_used[l])
                        interface_send_to_local_flush(&fwd->locals[l]);
                }

                interface_recv_release(wan, addrs, rcvd);
            }
        }

        // Print stats periodically
        if (loop_count % 1000000 == 0) {
            uint64_t total = fwd->local_to_wan + fwd->wan_to_local;
            if (total != last_stats) {
                printf("[FWD] L→W: %lu | W→L: %lu | Drop: %lu | WAN[%d]\n",
                       fwd->local_to_wan, fwd->wan_to_local, fwd->total_dropped,
                       fwd->current_wan);
                last_stats = total;
            }
        }
    }

    printf("\n[FWD] ══════════════════════════════════════════════════\n");
    printf("[FWD] Final Stats:\n");
    printf("[FWD]   LOCAL → WAN: %lu packets\n", fwd->local_to_wan);
    printf("[FWD]   WAN → LOCAL: %lu packets\n", fwd->wan_to_local);
    printf("[FWD]   Dropped:     %lu packets\n", fwd->total_dropped);
    printf("[FWD] ══════════════════════════════════════════════════\n");
}

void forwarder_print_stats(struct forwarder *fwd)
{
    printf("LOCAL→WAN: %lu | WAN→LOCAL: %lu | Dropped: %lu\n",
           fwd->local_to_wan, fwd->wan_to_local, fwd->total_dropped);
}
