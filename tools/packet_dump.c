/*
 * Packet Dump Tool
 *
 * Nhận packet qua AF_XDP và in ra nội dung raw
 * Dùng để check packet đã mã hóa chưa
 *
 * Usage: sudo ./packet_dump <interface> [count]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#define FRAME_SIZE 4096
#define NUM_FRAMES 4096
#define BATCH_SIZE 64

static volatile int running = 1;

static void sigint_handler(int sig) {
    (void)sig;
    running = 0;
}

static void print_packet(uint8_t *pkt, int len, int pkt_num)
{
    printf("\n========== PACKET #%d (len=%d) ==========\n", pkt_num, len);

    // ETH header
    printf("ETH: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x [Type: %02x%02x]\n",
           pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11],
           pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5],
           pkt[12], pkt[13]);

    // Payload (sau ETH header)
    printf("PAYLOAD (byte 14 trở đi):\n");
    int print_len = (len - 14 > 64) ? 64 : (len - 14);
    for (int i = 0; i < print_len; i++) {
        if (i % 16 == 0) printf("  %04x: ", i);
        printf("%02x ", pkt[14 + i]);
        if (i % 16 == 15) printf("\n");
    }
    if (print_len % 16 != 0) printf("\n");
    if (len - 14 > 64) printf("  ... (%d bytes more)\n", len - 14 - 64);

    // Check if looks like IPv4
    if (len > 14 && pkt[14] == 0x45) {
        printf(">>> Có vẻ là IPv4 (byte đầu = 0x45) - KHÔNG MÃ HÓA\n");
    } else {
        printf(">>> Không phải IPv4 header - CÓ THỂ ĐÃ MÃ HÓA\n");
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <interface> [count]\n", argv[0]);
        printf("Example: %s enp4s0 10\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int max_count = (argc > 2) ? atoi(argv[2]) : 0;
    int ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", ifname);
        return 1;
    }

    printf("============================================\n");
    printf("PACKET DUMP - Interface: %s\n", ifname);
    printf("Press Ctrl+C to stop\n");
    printf("============================================\n");

    // Allocate UMEM
    void *umem_area;
    if (posix_memalign(&umem_area, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        perror("posix_memalign");
        return 1;
    }

    struct xsk_umem *umem;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;

    struct xsk_umem_config umem_cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0
    };

    if (xsk_umem__create(&umem, umem_area, NUM_FRAMES * FRAME_SIZE, &fill, &comp, &umem_cfg)) {
        perror("xsk_umem__create");
        free(umem_area);
        return 1;
    }

    // Create XSK socket
    struct xsk_socket *xsk;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;

    struct xsk_socket_config xsk_cfg = {
        .rx_size = NUM_FRAMES,
        .tx_size = NUM_FRAMES,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .bind_flags = XDP_COPY
    };

    if (xsk_socket__create(&xsk, ifname, 0, umem, &rx, &tx, &xsk_cfg)) {
        perror("xsk_socket__create");
        xsk_umem__delete(umem);
        free(umem_area);
        return 1;
    }

    // Fill the fill ring
    uint32_t idx;
    if (xsk_ring_prod__reserve(&fill, NUM_FRAMES, &idx) != NUM_FRAMES) {
        fprintf(stderr, "Failed to reserve fill ring\n");
        goto cleanup;
    }
    for (uint32_t i = 0; i < NUM_FRAMES; i++) {
        *xsk_ring_prod__fill_addr(&fill, idx++) = i * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&fill, NUM_FRAMES);

    signal(SIGINT, sigint_handler);

    int pkt_count = 0;

    while (running) {
        uint32_t rcvd = xsk_ring_cons__peek(&rx, BATCH_SIZE, &idx);

        if (rcvd == 0) {
            usleep(1000);
            continue;
        }

        for (uint32_t i = 0; i < rcvd; i++) {
            const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&rx, idx + i);
            uint8_t *pkt = (uint8_t *)umem_area + desc->addr;

            print_packet(pkt, desc->len, ++pkt_count);

            if (max_count > 0 && pkt_count >= max_count) {
                running = 0;
                break;
            }
        }

        xsk_ring_cons__release(&rx, rcvd);

        // Refill
        if (xsk_ring_prod__reserve(&fill, rcvd, &idx) == rcvd) {
            for (uint32_t i = 0; i < rcvd; i++) {
                *xsk_ring_prod__fill_addr(&fill, idx + i) = (idx + i) * FRAME_SIZE;
            }
            xsk_ring_prod__submit(&fill, rcvd);
        }
    }

    printf("\n\nTotal: %d packets\n", pkt_count);

cleanup:
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    free(umem_area);
    return 0;
}
