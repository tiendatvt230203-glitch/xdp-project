#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "../inc/config.h"
#include "../inc/interface.h"
#include "../inc/packet_crypto.h"

static volatile int running = 1;
static struct packet_crypto_ctx crypto_ctx;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void print_hex(const uint8_t *data, int len, int max_len)
{
    int print_len = (len > max_len) ? max_len : len;
    for (int i = 0; i < print_len; i++) {
        if (i % 16 == 0) printf("  %04x: ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (print_len % 16 != 0) printf("\n");
    if (len > max_len) printf("  ... (%d bytes more)\n", len - max_len);
}

static void print_packet(uint8_t *pkt, int len, int pkt_num, const char *label, const char *wan_name)
{
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║ [%s] [%s] PACKET #%d (len=%d)                    \n", wan_name, label, pkt_num, len);
    printf("╠══════════════════════════════════════════════════════════════╣\n");

    printf("║ ETH: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
           pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11],
           pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
    printf("║ EtherType: 0x%02x%02x\n", pkt[12], pkt[13]);

    printf("╟──────────────────────────────────────────────────────────────╢\n");
    printf("║ PAYLOAD:\n");
    print_hex(pkt + 14, len - 14, 64);
    printf("╚══════════════════════════════════════════════════════════════╝\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <config.cfg> [count]\n", argv[0]);
        printf("\nDump packets from WAN after decryption (before LOCAL)\n");
        return 1;
    }

    int max_count = 10;
    if (argc >= 3) max_count = atoi(argv[2]);

    struct app_config cfg;
    if (config_load(&cfg, argv[1]) != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }

    config_print(&cfg);

    if (cfg.crypto_enabled) {
        if (packet_crypto_init(&crypto_ctx, cfg.crypto_key, cfg.crypto_iv) != 0) {
            fprintf(stderr, "Failed to init crypto\n");
            return 1;
        }
        if (cfg.fake_ethertype != 0) {
            packet_crypto_set_fake_ethertype(&crypto_ctx, cfg.fake_ethertype);
            printf("Crypto: ENABLED (fake_ethertype=0x%04X)\n", cfg.fake_ethertype);
        } else {
            printf("Crypto: ENABLED (zero overhead)\n");
        }
    } else {
        printf("Crypto: DISABLED\n");
    }

    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count = 0;

    for (int i = 0; i < cfg.wan_count; i++) {
        if (interface_init_wan_rx(&wans[i], &cfg.wans[i], "bpf/xdp_wan_redirect.o") != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg.wans[i].ifname);
            continue;
        }
        wan_count++;
        printf("Initialized WAN: %s\n", cfg.wans[i].ifname);
    }

    if (wan_count == 0) {
        fprintf(stderr, "No WAN interfaces initialized\n");
        return 1;
    }

    printf("\nListening on %d WAN interfaces...\n", wan_count);
    printf("Press Ctrl+C to stop\n\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    void *pkt_ptrs[64];
    uint32_t pkt_lens[64];
    uint64_t addrs[64];
    int pkt_count = 0;

    while (running && pkt_count < max_count) {
        for (int w = 0; w < wan_count && pkt_count < max_count; w++) {
            int rcvd = interface_recv(&wans[w], pkt_ptrs, pkt_lens, addrs, 64);
            if (rcvd > 0) {
                for (int i = 0; i < rcvd && pkt_count < max_count; i++) {
                    pkt_count++;

                    printf("\n>>> BEFORE DECRYPT:\n");
                    print_packet(pkt_ptrs[i], pkt_lens[i], pkt_count, "ENCRYPTED", cfg.wans[w].ifname);

                    if (cfg.crypto_enabled) {
                        // Zero overhead decryption - packet size unchanged
                        if (packet_decrypt(&crypto_ctx, pkt_ptrs[i], pkt_lens[i]) == 0) {
                            printf("\n>>> AFTER DECRYPT (size unchanged):\n");
                            print_packet(pkt_ptrs[i], pkt_lens[i], pkt_count, "PLAIN", cfg.wans[w].ifname);
                        } else {
                            printf(">>> DECRYPT FAILED\n");
                        }
                    }
                }
                interface_recv_release(&wans[w], addrs, rcvd);
            }
        }
    }

    printf("\n\nCaptured %d packets\n", pkt_count);

    for (int i = 0; i < wan_count; i++) {
        interface_cleanup(&wans[i]);
    }
    if (cfg.crypto_enabled) {
        packet_crypto_cleanup(&crypto_ctx);
    }

    return 0;
}
