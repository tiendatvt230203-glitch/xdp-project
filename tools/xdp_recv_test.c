#include "../inc/interface.h"
#include "../inc/config.h"
#include <signal.h>
#include <time.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <arpa/inet.h>

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

static const char *proto_name(uint8_t proto)
{
    switch (proto) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        default: return "OTHER";
    }
}

static void print_packet(void *pkt, uint32_t len, uint64_t count)
{
    struct ether_header *eth = (struct ether_header *)pkt;

    printf("[%lu] len=%u ", count, len);

    // Print MACs
    printf("src=%02x:%02x:%02x:%02x:%02x:%02x ",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("dst=%02x:%02x:%02x:%02x:%02x:%02x ",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        struct iphdr *ip = (struct iphdr *)((uint8_t *)pkt + sizeof(struct ether_header));

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

        printf("IP %s -> %s proto=%s", src_ip, dst_ip, proto_name(ip->protocol));

        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)((uint8_t *)ip + (ip->ihl * 4));
            printf(" sport=%u dport=%u", ntohs(udp->source), ntohs(udp->dest));
        } else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)((uint8_t *)ip + (ip->ihl * 4));
            printf(" sport=%u dport=%u", ntohs(tcp->source), ntohs(tcp->dest));
        }
    } else {
        printf("EtherType=0x%04x", ntohs(eth->ether_type));
    }

    printf("\n");
}

int main(int argc, char **argv)
{
    struct app_config cfg;
    struct xsk_interface local;
    const char *config_file = "config.cfg";
    int verbose = 1;

    if (argc > 1)
        config_file = argv[1];
    if (argc > 2 && strcmp(argv[2], "-q") == 0)
        verbose = 0;

    printf("=== XDP Redirect Receive Test ===\n");
    printf("Config: %s\n", config_file);
    printf("Press Ctrl+C to stop\n\n");

    if (config_load(&cfg, config_file) != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }

    if (cfg.local_count == 0) {
        fprintf(stderr, "No LOCAL interface in config\n");
        return 1;
    }

    printf("Initializing LOCAL interface: %s\n", cfg.locals[0].ifname);
    printf("  Network: %u.%u.%u.%u/%u.%u.%u.%u\n",
           (cfg.locals[0].network >> 0) & 0xFF,
           (cfg.locals[0].network >> 8) & 0xFF,
           (cfg.locals[0].network >> 16) & 0xFF,
           (cfg.locals[0].network >> 24) & 0xFF,
           (cfg.locals[0].netmask >> 0) & 0xFF,
           (cfg.locals[0].netmask >> 8) & 0xFF,
           (cfg.locals[0].netmask >> 16) & 0xFF,
           (cfg.locals[0].netmask >> 24) & 0xFF);

    if (interface_init_local(&local, &cfg.locals[0], cfg.bpf_file) != 0) {
        fprintf(stderr, "Failed to init LOCAL interface\n");
        return 1;
    }

    printf("\nXDP loaded. Waiting for packets...\n");
    printf("(Packets destined to local network will be passed to kernel)\n");
    printf("(Packets destined elsewhere will be redirected here)\n\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    void *pkt_ptrs[BATCH_SIZE];
    uint32_t pkt_lens[BATCH_SIZE];
    uint64_t addrs[BATCH_SIZE];

    uint64_t total_pkts = 0;
    uint64_t total_bytes = 0;
    struct timespec start, now, last_stat;
    clock_gettime(CLOCK_MONOTONIC, &start);
    last_stat = start;

    while (running) {
        int rcvd = interface_recv(&local, pkt_ptrs, pkt_lens, addrs, BATCH_SIZE);

        if (rcvd > 0) {
            for (int i = 0; i < rcvd; i++) {
                total_pkts++;
                total_bytes += pkt_lens[i];

                if (verbose)
                    print_packet(pkt_ptrs[i], pkt_lens[i], total_pkts);
            }

            interface_recv_release(&local, addrs, rcvd);
        }

        // Print stats every second
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - last_stat.tv_sec) +
                        (now.tv_nsec - last_stat.tv_nsec) / 1e9;

        if (elapsed >= 1.0) {
            double total_elapsed = (now.tv_sec - start.tv_sec) +
                                  (now.tv_nsec - start.tv_nsec) / 1e9;
            double pps = total_pkts / total_elapsed;
            double mbps = (total_bytes * 8.0) / (total_elapsed * 1e6);

            printf("\n--- Stats: %lu pkts, %.2f MB, %.0f pps, %.2f Mbps ---\n\n",
                   total_pkts, total_bytes / 1e6, pps, mbps);

            last_stat = now;
        }
    }

    printf("\n=== Final Stats ===\n");
    printf("Total packets: %lu\n", total_pkts);
    printf("Total bytes: %lu (%.2f MB)\n", total_bytes, total_bytes / 1e6);

    interface_cleanup(&local);

    return 0;
}
