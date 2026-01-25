/*
 * High-Performance Packet Generator
 * Optimized for 2.5Gbps+ throughput
 *
 * Features:
 * - sendmmsg() for batch sending
 * - Pre-built packets
 * - Minimal syscall overhead
 *
 * Usage: ./pkt_gen <interface> <dst_ip> <seconds>
 * Example: ./pkt_gen enp7s0 192.168.182.2 10
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

#define PKT_SIZE    1500
#define BATCH_SIZE  64      // Số packet mỗi lần sendmmsg
#define SRC_PORT    12345
#define DST_PORT    5001

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

static uint16_t checksum(void *data, int len)
{
    uint32_t sum = 0;
    uint16_t *ptr = data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)ptr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("Usage: %s <interface> <dst_ip> <seconds>\n", argv[0]);
        printf("Example: %s enp7s0 192.168.182.2 10\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    const char *dst_ip_str = argv[2];
    int duration = atoi(argv[3]);

    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Set socket buffer size for performance
    int bufsize = 16 * 1024 * 1024;  // 16MB
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    // Get interface info
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return 1;
    }
    int ifindex = ifr.ifr_ifindex;

    // HARDCODE MAC addresses
    // Client01 enp7s0 MAC (source - sender)
    uint8_t src_mac[6] = {0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x08};

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(sock);
        return 1;
    }
    uint32_t src_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    uint32_t dst_ip;
    inet_pton(AF_INET, dst_ip_str, &dst_ip);

    // Server01 enp7s0 MAC (destination - gateway)
    uint8_t dst_mac[6] = {0x20, 0x7c, 0x14, 0xf8, 0x0c, 0xd2};

    // Bind to interface
    struct sockaddr_ll saddr = {0};
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_IP);
    saddr.sll_ifindex = ifindex;
    saddr.sll_halen = 6;
    memcpy(saddr.sll_addr, dst_mac, 6);

    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    // Pre-allocate packet buffers for batch sending
    uint8_t *pkts[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];

    for (int i = 0; i < BATCH_SIZE; i++) {
        pkts[i] = aligned_alloc(64, PKT_SIZE);  // Cache-aligned
        memset(pkts[i], 0, PKT_SIZE);

        // Build Ethernet header
        struct ethhdr *eth = (struct ethhdr *)pkts[i];
        memcpy(eth->h_dest, dst_mac, 6);
        memcpy(eth->h_source, src_mac, 6);
        eth->h_proto = htons(ETH_P_IP);

        // Build IP header
        struct iphdr *ip = (struct iphdr *)(pkts[i] + sizeof(struct ethhdr));
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(PKT_SIZE - sizeof(struct ethhdr));
        ip->id = htons(i);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr = src_ip;
        ip->daddr = dst_ip;
        ip->check = 0;
        ip->check = checksum(ip, sizeof(struct iphdr));

        // Build UDP header
        struct udphdr *udp = (struct udphdr *)(pkts[i] + sizeof(struct ethhdr) + sizeof(struct iphdr));
        udp->source = htons(SRC_PORT);
        udp->dest = htons(DST_PORT);
        udp->len = htons(PKT_SIZE - sizeof(struct ethhdr) - sizeof(struct iphdr));
        udp->check = 0;

        // Fill payload
        uint8_t *payload = pkts[i] + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
        int payload_len = PKT_SIZE - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);
        memset(payload, 'X', payload_len);

        // Setup iovec and mmsghdr
        iovecs[i].iov_base = pkts[i];
        iovecs[i].iov_len = PKT_SIZE;

        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    printf("╔════════════════════════════════════════════════╗\n");
    printf("║     HIGH-PERFORMANCE PACKET GENERATOR          ║\n");
    printf("╠════════════════════════════════════════════════╣\n");
    printf("║ Interface: %-36s ║\n", ifname);

    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip, src_ip_str, sizeof(src_ip_str));
    printf("║ Src IP:    %-36s ║\n", src_ip_str);
    printf("║ Dst IP:    %-36s ║\n", dst_ip_str);
    printf("║ Pkt Size:  %-36d ║\n", PKT_SIZE);
    printf("║ Batch:     %-36d ║\n", BATCH_SIZE);
    printf("║ Duration:  %-33d sec ║\n", duration);
    printf("╚════════════════════════════════════════════════╝\n\n");

    signal(SIGINT, sigint_handler);

    printf("Sending at maximum rate for %d seconds...\n", duration);
    printf("Press Ctrl+C to stop\n\n");

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint64_t total_sent = 0;
    uint64_t total_bytes = 0;
    uint64_t batch_count = 0;

    while (running) {
        // Check duration
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= duration)
            break;

        // Send batch using sendmmsg (one syscall for multiple packets)
        int sent = sendmmsg(sock, msgs, BATCH_SIZE, 0);
        if (sent > 0) {
            total_sent += sent;
            total_bytes += sent * PKT_SIZE;
            batch_count++;
        }

        // Print stats every 100K batches
        if (batch_count % 100000 == 0) {
            double rate_gbps = (total_bytes * 8.0) / elapsed / 1e9;
            printf("\rSent: %lu pkts | %.2f Gbps | %.2f Mpps",
                   total_sent, rate_gbps, total_sent / elapsed / 1e6);
            fflush(stdout);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;

    printf("\n\n╔════════════════════════════════════════════════╗\n");
    printf("║                   RESULTS                       ║\n");
    printf("╠════════════════════════════════════════════════╣\n");
    printf("║ Total Packets: %-32lu ║\n", total_sent);
    printf("║ Total Bytes:   %-32lu ║\n", total_bytes);
    printf("║ Time:          %-29.2f sec ║\n", elapsed);
    printf("║ Rate:          %-29.2f Mpps ║\n", total_sent / elapsed / 1e6);
    printf("║ Throughput:    %-29.2f Gbps ║\n", (total_bytes * 8.0) / elapsed / 1e9);
    printf("╚════════════════════════════════════════════════╝\n");

    // Cleanup
    for (int i = 0; i < BATCH_SIZE; i++)
        free(pkts[i]);
    close(sock);

    return 0;
}
