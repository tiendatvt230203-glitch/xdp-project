#include "../inc/interface.h"
#include "../inc/config.h"
#include <signal.h>
#include <time.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define LB_WINDOW_SIZE (64 * 1024)
#define TEST_PKT_SIZE 1400
#define TARGET_MBPS 100

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

// Simple load balancer state
struct lb_state {
    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;
    int current_wan;
    uint64_t window_bytes;
    uint64_t tx_per_wan[MAX_INTERFACES];
    uint64_t bytes_per_wan[MAX_INTERFACES];
};

static struct xsk_interface *get_wan(struct lb_state *lb, uint32_t pkt_len)
{
    lb->window_bytes += pkt_len;
    if (lb->window_bytes >= LB_WINDOW_SIZE) {
        lb->current_wan = (lb->current_wan + 1) % lb->wan_count;
        lb->window_bytes = 0;
    }
    return &lb->wans[lb->current_wan];
}

// Build fake IP/UDP packet
static void build_packet(uint8_t *pkt, int len)
{
    struct ether_header *eth = (struct ether_header *)pkt;
    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ether_header));
    struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + sizeof(struct iphdr));

    memset(pkt, 0, len);

    // Ethernet header (MACs will be rewritten by interface_send)
    eth->ether_type = htons(0x0800);

    // IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tot_len = htons(len - sizeof(struct ether_header));
    ip->ttl = 64;
    ip->protocol = 17; // UDP
    ip->saddr = htonl(0xC0A80901); // 192.168.9.1
    ip->daddr = htonl(0xC0A8B602); // 192.168.182.2

    // UDP header
    udp->source = htons(12345);
    udp->dest = htons(54321);
    udp->len = htons(len - sizeof(struct ether_header) - sizeof(struct iphdr));
}

int main(int argc, char **argv)
{
    struct app_config cfg;
    struct lb_state lb;
    uint8_t pkt[TEST_PKT_SIZE];
    const char *config_file = "config.txt";

    if (argc > 1)
        config_file = argv[1];

    printf("=== Load Balancer Test (bypass XDP) ===\n");
    printf("Config: %s\n", config_file);
    printf("Packet size: %d bytes\n", TEST_PKT_SIZE);
    printf("Target rate: %d Mbps\n", TARGET_MBPS);
    printf("Window size: %d KB\n", LB_WINDOW_SIZE / 1024);
    printf("\n");

    if (config_load(&cfg, config_file) != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }

    if (cfg.wan_count == 0) {
        fprintf(stderr, "No WAN interfaces in config\n");
        return 1;
    }

    memset(&lb, 0, sizeof(lb));

    // Initialize WAN interfaces only (skip LOCAL/XDP)
    printf("Initializing WAN interfaces...\n");
    for (int i = 0; i < cfg.wan_count; i++) {
        printf("  [%d] %s -> MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               i, cfg.wans[i].ifname,
               cfg.wans[i].dst_mac[0], cfg.wans[i].dst_mac[1],
               cfg.wans[i].dst_mac[2], cfg.wans[i].dst_mac[3],
               cfg.wans[i].dst_mac[4], cfg.wans[i].dst_mac[5]);

        if (interface_init_wan(&lb.wans[i], &cfg.wans[i]) != 0) {
            fprintf(stderr, "Failed to init WAN %s\n", cfg.wans[i].ifname);
            for (int j = 0; j < i; j++)
                interface_cleanup(&lb.wans[j]);
            return 1;
        }
        lb.wan_count++;
    }

    printf("\nAll WANs initialized. Starting packet generation...\n\n");

    // Build template packet
    build_packet(pkt, TEST_PKT_SIZE);

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    // Calculate delay between packets for target rate
    // packets_per_sec = (TARGET_MBPS * 1000000) / (TEST_PKT_SIZE * 8)
    uint64_t packets_per_sec = (TARGET_MBPS * 1000000ULL) / (TEST_PKT_SIZE * 8);
    uint64_t delay_ns = 1000000000ULL / packets_per_sec;

    printf("Sending %lu pkt/s (delay: %lu ns)\n", packets_per_sec, delay_ns);
    printf("Press Ctrl+C to stop\n\n");

    struct timespec start, now, last_stat;
    clock_gettime(CLOCK_MONOTONIC, &start);
    last_stat = start;

    uint64_t total_sent = 0;
    uint64_t total_failed = 0;

    while (running) {
        struct xsk_interface *wan = get_wan(&lb, TEST_PKT_SIZE);
        int wan_idx = lb.current_wan;

        if (interface_send(wan, pkt, TEST_PKT_SIZE) == 0) {
            total_sent++;
            lb.tx_per_wan[wan_idx]++;
            lb.bytes_per_wan[wan_idx] += TEST_PKT_SIZE;
        } else {
            total_failed++;
        }

        // Rate limiting
        struct timespec req = {0, delay_ns};
        nanosleep(&req, NULL);

        // Print stats every second
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - last_stat.tv_sec) +
                        (now.tv_nsec - last_stat.tv_nsec) / 1e9;

        if (elapsed >= 1.0) {
            double total_elapsed = (now.tv_sec - start.tv_sec) +
                                  (now.tv_nsec - start.tv_nsec) / 1e9;
            double mbps = (total_sent * TEST_PKT_SIZE * 8.0) / (total_elapsed * 1e6);

            printf("\r[%.1fs] Sent: %lu (%.1f Mbps) | Failed: %lu | ",
                   total_elapsed, total_sent, mbps, total_failed);

            for (int i = 0; i < lb.wan_count; i++) {
                printf("WAN%d: %lu ", i, lb.tx_per_wan[i]);
            }
            fflush(stdout);

            last_stat = now;
        }
    }

    printf("\n\n=== Final Stats ===\n");
    printf("Total sent: %lu\n", total_sent);
    printf("Total failed: %lu\n", total_failed);
    printf("\nPer-WAN distribution:\n");
    for (int i = 0; i < lb.wan_count; i++) {
        double pct = (total_sent > 0) ? (lb.tx_per_wan[i] * 100.0 / total_sent) : 0;
        printf("  WAN%d (%s): %lu pkts, %.1f MB (%.1f%%)\n",
               i, lb.wans[i].ifname,
               lb.tx_per_wan[i],
               lb.bytes_per_wan[i] / 1e6,
               pct);
    }

    // Cleanup
    for (int i = 0; i < lb.wan_count; i++)
        interface_cleanup(&lb.wans[i]);

    return 0;
}
