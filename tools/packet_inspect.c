/*
 * Packet Inspector Tool
 *
 * Bắt packet trên interface và hiển thị:
 * - Raw packet (trước giải mã)
 * - Decrypted packet (sau giải mã)
 *
 * Dùng để verify encryption đang hoạt động
 *
 * Usage: ./packet_inspect <interface> [count]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "../inc/packet_crypto.h"

static volatile int running = 1;

// Test key/IV (same as default in config)
static const uint8_t test_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t test_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

static void print_hex_dump(const char *label, const uint8_t *data, int len, int max_len)
{
    printf("%s (%d bytes):\n", label, len);
    int print_len = (len < max_len) ? len : max_len;

    for (int i = 0; i < print_len; i++) {
        if (i % 16 == 0) printf("  %04x: ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 15) printf("\n");
    }
    if (print_len % 16 != 0) printf("\n");
    if (len > max_len) printf("  ... (%d bytes more)\n", len - max_len);
}

static void print_eth_header(const uint8_t *pkt)
{
    struct ether_header *eth = (struct ether_header *)pkt;

    printf("  ETH: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5],
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf(" Type: 0x%04x\n", ntohs(eth->ether_type));
}

static int try_parse_ip(const uint8_t *pkt, int len)
{
    if (len < (int)(sizeof(struct ether_header) + sizeof(struct iphdr))) {
        return 0;
    }

    struct ether_header *eth = (struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return 0;
    }

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ether_header));

    // Validate IP header
    if (ip->version != 4) return 0;
    if (ip->ihl < 5) return 0;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

    printf("  IP:  %s -> %s (proto: %d, len: %d)\n",
           src_ip, dst_ip, ip->protocol, ntohs(ip->tot_len));

    return 1;
}

static void analyze_packet(const uint8_t *pkt, int len, struct packet_crypto_ctx *crypto)
{
    static int pkt_num = 0;
    pkt_num++;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║ PACKET #%d                                                        ║\n", pkt_num);
    printf("╠══════════════════════════════════════════════════════════════════╣\n");

    // 1. Show Ethernet header (always readable)
    printf("║ [LAYER 2 - Ethernet Header]                                      ║\n");
    print_eth_header(pkt);

    // 2. Show raw payload (potentially encrypted)
    printf("╟──────────────────────────────────────────────────────────────────╢\n");
    printf("║ [RAW PAYLOAD - After ETH header]                                 ║\n");
    print_hex_dump("  Raw", pkt + 14, len - 14, 64);

    // 3. Try to parse as IP (if not encrypted, this works)
    printf("╟──────────────────────────────────────────────────────────────────╢\n");
    printf("║ [TRY PARSE AS IPv4]                                              ║\n");
    if (try_parse_ip(pkt, len)) {
        printf("  ✅ KHÔNG MÃ HÓA - Parse IP header thành công!\n");
    } else {
        printf("  ❌ Không parse được IP - Có thể đã MÃ HÓA\n");

        // 4. Try to decrypt
        if (crypto && len > 14 + CRYPTO_NONCE_SIZE) {
            printf("╟──────────────────────────────────────────────────────────────────╢\n");
            printf("║ [THỬ GIẢI MÃ]                                                    ║\n");

            // Copy packet to decrypt
            uint8_t decrypted[2048];
            memcpy(decrypted, pkt, len);

            int dec_len = packet_decrypt(crypto, decrypted, len);
            if (dec_len > 0) {
                printf("  Decrypted length: %d\n", dec_len);
                print_hex_dump("  Decrypted payload", decrypted + 14, dec_len - 14, 64);

                if (try_parse_ip(decrypted, dec_len)) {
                    printf("  ✅ GIẢI MÃ THÀNH CÔNG - Packet đã được mã hóa!\n");
                } else {
                    printf("  ⚠️  Giải mã xong nhưng vẫn không parse được IP\n");
                    printf("      (Có thể key/IV không đúng hoặc packet không phải IP)\n");
                }
            } else {
                printf("  ❌ Giải mã thất bại (key/IV không đúng?)\n");
            }
        }
    }

    printf("╚══════════════════════════════════════════════════════════════════╝\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <interface> [count] [key_hex] [iv_hex]\n", argv[0]);
        printf("\n");
        printf("Examples:\n");
        printf("  %s enp4s0              # Capture on enp4s0, infinite\n", argv[0]);
        printf("  %s enp4s0 10           # Capture 10 packets\n", argv[0]);
        printf("  %s enp4s0 10 <key> <iv> # Use custom key/IV\n", argv[0]);
        printf("\n");
        printf("Key/IV format: 32 hex characters (e.g., 2b7e151628aed2a6abf7158809cf4f3c)\n");
        return 1;
    }

    const char *ifname = argv[1];
    int max_count = (argc > 2) ? atoi(argv[2]) : 0;

    // Initialize crypto context
    struct packet_crypto_ctx crypto;
    uint8_t key[16], iv[16];

    if (argc > 4) {
        // Parse custom key/IV
        for (int i = 0; i < 16; i++) {
            sscanf(argv[3] + i*2, "%2hhx", &key[i]);
            sscanf(argv[4] + i*2, "%2hhx", &iv[i]);
        }
    } else {
        memcpy(key, test_key, 16);
        memcpy(iv, test_iv, 16);
    }

    if (packet_crypto_init(&crypto, key, iv) != 0) {
        fprintf(stderr, "Failed to init crypto\n");
        return 1;
    }

    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Bind to interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    signal(SIGINT, sigint_handler);

    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║              PACKET INSPECTOR - Check Encryption                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║ Interface: %-54s ║\n", ifname);
    printf("║ Packets:   %-54s ║\n", max_count > 0 ? "limited" : "unlimited (Ctrl+C to stop)");
    printf("║ Key:       %02x%02x%02x%02x%02x%02x%02x%02x...                              ║\n",
           key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\nWaiting for packets...\n");

    uint8_t buffer[2048];
    int count = 0;

    while (running) {
        int len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            if (running) perror("recv");
            break;
        }

        if (len < 14) continue;  // Skip invalid packets

        analyze_packet(buffer, len, &crypto);

        count++;
        if (max_count > 0 && count >= max_count) {
            break;
        }
    }

    printf("\n\nCaptured %d packets.\n", count);

    close(sock);
    packet_crypto_cleanup(&crypto);

    return 0;
}
