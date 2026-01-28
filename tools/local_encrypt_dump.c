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

static void print_packet(uint8_t *pkt, int len, int pkt_num, const char *label)
{
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║ [%s] PACKET #%d (len=%d)                            \n", label, pkt_num, len);
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
        printf("\nDump packets from LOCAL after encryption (before WAN)\n");
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
        packet_crypto_set_fake_ethertype(cfg.fake_ethertype);
        printf("Crypto: ENABLED\n");
    } else {
        printf("Crypto: DISABLED\n");
    }

    struct xsk_interface local;
    if (interface_init_local(&local, &cfg.locals[0], cfg.bpf_file) != 0) {
        fprintf(stderr, "Failed to init LOCAL %s\n", cfg.locals[0].ifname);
        return 1;
    }

    printf("\nListening on LOCAL %s...\n", cfg.locals[0].ifname);
    printf("Press Ctrl+C to stop\n\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    void *pkt_ptrs[64];
    uint32_t pkt_lens[64];
    uint64_t addrs[64];
    int pkt_count = 0;

    while (running && pkt_count < max_count) {
        int rcvd = interface_recv(&local, pkt_ptrs, pkt_lens, addrs, 64);
        if (rcvd > 0) {
            for (int i = 0; i < rcvd && pkt_count < max_count; i++) {
                pkt_count++;

                printf("\n>>> BEFORE ENCRYPT:\n");
                print_packet(pkt_ptrs[i], pkt_lens[i], pkt_count, "PLAIN");

                if (cfg.crypto_enabled) {
                    int new_len = packet_encrypt(&crypto_ctx, pkt_ptrs[i], pkt_lens[i]);
                    if (new_len > 0) {
                        pkt_lens[i] = new_len;
                        printf("\n>>> AFTER ENCRYPT:\n");
                        print_packet(pkt_ptrs[i], pkt_lens[i], pkt_count, "ENCRYPTED");
                    } else {
                        printf(">>> ENCRYPT FAILED\n");
                    }
                }
            }
            interface_recv_release(&local, addrs, rcvd);
        }
    }

    printf("\n\nCaptured %d packets\n", pkt_count);

    interface_cleanup(&local);
    if (cfg.crypto_enabled) {
        packet_crypto_cleanup(&crypto_ctx);
    }

    return 0;
}
