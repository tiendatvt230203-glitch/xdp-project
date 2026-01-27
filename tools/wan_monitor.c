/*
 * WAN Monitor - Bắt packet trên 3 WAN interfaces
 *
 * Hiển thị rõ ràng:
 * - Layer 2 (Ethernet) - KHÔNG MÃ HÓA
 * - Nonce (8 bytes)
 * - Layer 3/4/7 - ĐÃ MÃ HÓA
 *
 * Usage: sudo ./wan_monitor [count]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define NUM_INTERFACES 3
#define ETH_HDR_LEN 14
#define NONCE_LEN 8
#define ORIG_TYPE_LEN 2

/* Known fake ethertypes */
#define FAKE_TYPE_88B5 0x88B5
#define FAKE_TYPE_88B6 0x88B6
#define FAKE_TYPE_9000 0x9000

static const char *wan_interfaces[NUM_INTERFACES] = {
    "enp4s0",
    "enp5s0",
    "enp6s0"
};

static volatile int running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static void print_hex(const uint8_t *data, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
    }
}

static const char *get_ethertype_name(uint16_t type)
{
    switch (type) {
        case 0x0800: return "IPv4";
        case 0x86DD: return "IPv6";
        case 0x0806: return "ARP";
        case 0x88B5: return "FAKE (88B5)";
        case 0x88B6: return "FAKE (88B6)";
        case 0x9000: return "FAKE (9000)";
        case 0x8100: return "VLAN";
        default: return "Unknown";
    }
}

static int is_fake_ethertype(uint16_t type)
{
    return (type == FAKE_TYPE_88B5 || type == FAKE_TYPE_88B6 || type == FAKE_TYPE_9000);
}

static void print_packet(const char *ifname, uint8_t *pkt, int len, int pkt_num)
{
    uint16_t ethertype = (pkt[12] << 8) | pkt[13];
    int is_fake = is_fake_ethertype(ethertype);

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║ PACKET #%-4d | Interface: %-10s | Size: %-4d bytes            ║\n",
           pkt_num, ifname, len);
    printf("╠════════════════════════════════════════════════════════════════════╣\n");

    /* Layer 2 - Ethernet Header (14 bytes) - KHÔNG MÃ HÓA */
    printf("║ [LAYER 2 - Ethernet] KHÔNG MÃ HÓA                                  ║\n");
    printf("║   Src MAC: %02x:%02x:%02x:%02x:%02x:%02x                                      ║\n",
           pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11]);
    printf("║   Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x                                      ║\n",
           pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
    printf("║   Type:    0x%04X %-50s ║\n", ethertype, get_ethertype_name(ethertype));

    if (is_fake) {
        printf("║   >>> FAKE ETHERTYPE DETECTED - Protocol đã bị ẩn!                ║\n");
    }

    if (len <= ETH_HDR_LEN) {
        printf("╚════════════════════════════════════════════════════════════════════╝\n");
        return;
    }

    /* Nonce (8 bytes) */
    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    printf("║ [NONCE - 8 bytes] Dùng để giải mã                                  ║\n");
    printf("║   ");
    print_hex(pkt + ETH_HDR_LEN, (len - ETH_HDR_LEN >= NONCE_LEN) ? NONCE_LEN : len - ETH_HDR_LEN);
    printf("\n");

    if (len <= ETH_HDR_LEN + NONCE_LEN + ORIG_TYPE_LEN) {
        printf("╚════════════════════════════════════════════════════════════════════╝\n");
        return;
    }

    /* Original EtherType (2 bytes) - stored after nonce */
    uint16_t orig_type = (pkt[ETH_HDR_LEN + NONCE_LEN] << 8) | pkt[ETH_HDR_LEN + NONCE_LEN + 1];
    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    printf("║ [ORIG ETHERTYPE - 2 bytes] Protocol thật đã ẩn                     ║\n");
    printf("║   0x%04X (%s)                                                      ║\n",
           orig_type, get_ethertype_name(orig_type));

    /* Encrypted payload */
    int enc_offset = ETH_HDR_LEN + NONCE_LEN + ORIG_TYPE_LEN;
    int enc_len = len - enc_offset;

    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    printf("║ [LAYER 3/4/7 - Encrypted] %d bytes                                 ║\n", enc_len);
    printf("║   ");

    /* Print first 32 bytes of encrypted data */
    int print_len = (enc_len > 32) ? 32 : enc_len;
    print_hex(pkt + enc_offset, print_len);
    if (enc_len > 32) printf("...");
    printf("\n");

    /* Check if it looks encrypted */
    if (enc_len > 0 && pkt[enc_offset] == 0x45) {
        printf("║   >>> CẢNH BÁO: Byte đầu = 0x45 (IPv4) - CÓ THỂ KHÔNG MÃ HÓA!      ║\n");
    } else {
        printf("║   >>> OK: Không thấy IPv4 header - ĐÃ MÃ HÓA                       ║\n");
    }

    printf("╚════════════════════════════════════════════════════════════════════╝\n");
}

static int create_raw_socket(const char *ifname)
{
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    return sock;
}

int main(int argc, char *argv[])
{
    int max_count = (argc > 1) ? atoi(argv[1]) : 0;
    int sockets[NUM_INTERFACES];
    struct pollfd fds[NUM_INTERFACES];

    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    WAN MONITOR - Server02                          ║\n");
    printf("║  Bắt packet trên 3 WAN interfaces để verify encryption            ║\n");
    printf("╠════════════════════════════════════════════════════════════════════╣\n");

    /* Create sockets for all interfaces */
    for (int i = 0; i < NUM_INTERFACES; i++) {
        sockets[i] = create_raw_socket(wan_interfaces[i]);
        if (sockets[i] < 0) {
            printf("║  ✗ Failed to open: %-48s ║\n", wan_interfaces[i]);
            /* Cleanup already opened sockets */
            for (int j = 0; j < i; j++) {
                close(sockets[j]);
            }
            return 1;
        }
        printf("║  ✓ Listening on:  %-48s ║\n", wan_interfaces[i]);

        fds[i].fd = sockets[i];
        fds[i].events = POLLIN;
    }

    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    if (max_count > 0) {
        printf("║  Capturing %d packets... (Ctrl+C to stop)                          ║\n", max_count);
    } else {
        printf("║  Capturing unlimited packets... (Ctrl+C to stop)                   ║\n");
    }
    printf("╚════════════════════════════════════════════════════════════════════╝\n");

    signal(SIGINT, sigint_handler);

    uint8_t buffer[2048];
    int pkt_count = 0;
    int counts[NUM_INTERFACES] = {0, 0, 0};

    while (running) {
        int ret = poll(fds, NUM_INTERFACES, 1000);
        if (ret < 0) {
            if (running) perror("poll");
            break;
        }
        if (ret == 0) continue;

        for (int i = 0; i < NUM_INTERFACES; i++) {
            if (fds[i].revents & POLLIN) {
                int len = recv(sockets[i], buffer, sizeof(buffer), 0);
                if (len < 0) {
                    perror("recv");
                    continue;
                }
                if (len < 14) continue;

                pkt_count++;
                counts[i]++;
                print_packet(wan_interfaces[i], buffer, len, pkt_count);

                if (max_count > 0 && pkt_count >= max_count) {
                    running = 0;
                    break;
                }
            }
        }
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════╗\n");
    printf("║                           SUMMARY                                  ║\n");
    printf("╠════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total packets: %-50d ║\n", pkt_count);
    for (int i = 0; i < NUM_INTERFACES; i++) {
        printf("║    %-10s: %-46d ║\n", wan_interfaces[i], counts[i]);
    }
    printf("╚════════════════════════════════════════════════════════════════════╝\n");

    /* Cleanup */
    for (int i = 0; i < NUM_INTERFACES; i++) {
        close(sockets[i]);
    }

    return 0;
}
