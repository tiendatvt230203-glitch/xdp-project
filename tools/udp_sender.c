/*
 * High-Performance UDP Sender - Client1
 * Sends UDP traffic at maximum rate (2.5Gbps target)
 *
 * Usage: ./udp_sender <dst_ip> <seconds>
 * Example: ./udp_sender 192.168.182.2 10
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

#define PKT_SIZE    1400
#define BATCH_SIZE  64
#define DST_PORT    5001

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: %s <dst_ip> <seconds>\n", argv[0]);
        printf("Example: %s 192.168.182.2 10\n", argv[0]);
        return 1;
    }

    const char *dst_ip_str = argv[1];
    int duration = atoi(argv[2]);

    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Large socket buffer for high throughput
    int bufsize = 16 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    // Destination address
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(DST_PORT);
    inet_pton(AF_INET, dst_ip_str, &dst_addr.sin_addr);

    // Connect socket for faster sendmsg
    connect(sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

    // Pre-allocate batch buffers
    char payloads[BATCH_SIZE][PKT_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    struct mmsghdr msgs[BATCH_SIZE];

    for (int i = 0; i < BATCH_SIZE; i++) {
        memset(payloads[i], 'X', PKT_SIZE);
        iovecs[i].iov_base = payloads[i];
        iovecs[i].iov_len = PKT_SIZE;
        memset(&msgs[i], 0, sizeof(msgs[i]));
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    printf("========================================\n");
    printf("   HIGH-PERF UDP SENDER - CLIENT1\n");
    printf("========================================\n");
    printf("Dst IP:    %s\n", dst_ip_str);
    printf("Dst Port:  %d\n", DST_PORT);
    printf("Pkt Size:  %d bytes\n", PKT_SIZE);
    printf("Batch:     %d packets\n", BATCH_SIZE);
    printf("Duration:  %d sec\n", duration);
    printf("========================================\n\n");

    signal(SIGINT, sigint_handler);

    printf("Sending at MAX RATE for %d seconds...\n", duration);
    printf("Press Ctrl+C to stop\n\n");

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    uint64_t total_sent = 0;
    uint64_t total_bytes = 0;
    uint64_t loops = 0;

    while (running) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
        if (elapsed >= duration)
            break;

        // Batch send
        int sent = sendmmsg(sock, msgs, BATCH_SIZE, 0);
        if (sent > 0) {
            total_sent += sent;
            total_bytes += sent * PKT_SIZE;
        }

        // Print every 100K loops
        loops++;
        if (loops % 100000 == 0) {
            double rate_gbps = (total_bytes * 8.0) / elapsed / 1e9;
            printf("\rSent: %lu pkts | %.2f Gbps | %.2f Mpps",
                   total_sent, rate_gbps, total_sent / elapsed / 1e6);
            fflush(stdout);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;

    printf("\n\n========================================\n");
    printf("              RESULTS\n");
    printf("========================================\n");
    printf("Total Packets: %lu\n", total_sent);
    printf("Total Bytes:   %lu\n", total_bytes);
    printf("Time:          %.2f sec\n", elapsed);
    printf("Rate:          %.2f Mpps\n", total_sent / elapsed / 1e6);
    printf("Throughput:    %.2f Gbps\n", (total_bytes * 8.0) / elapsed / 1e9);
    printf("========================================\n");

    close(sock);
    return 0;
}
