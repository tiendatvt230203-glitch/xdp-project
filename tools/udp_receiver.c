/*
 * Simple UDP Receiver - Client2
 * Receives UDP traffic and counts packets
 *
 * Usage: ./udp_receiver
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

#define BUF_SIZE    2000
#define LISTEN_PORT 5001

static volatile int running = 1;

static void sigint_handler(int sig)
{
    (void)sig;
    running = 0;
}

int main()
{
    // Create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Bind to port
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    printf("========================================\n");
    printf("       UDP RECEIVER - CLIENT2\n");
    printf("========================================\n");
    printf("Listening on port %d\n", LISTEN_PORT);
    printf("Press Ctrl+C to stop\n");
    printf("========================================\n\n");

    signal(SIGINT, sigint_handler);

    char buf[BUF_SIZE];
    struct sockaddr_in src_addr;
    socklen_t src_len = sizeof(src_addr);

    uint64_t total_recv = 0;
    uint64_t total_bytes = 0;

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int started = 0;

    while (running) {
        ssize_t ret = recvfrom(sock, buf, BUF_SIZE, MSG_DONTWAIT,
                               (struct sockaddr *)&src_addr, &src_len);
        if (ret > 0) {
            if (!started) {
                clock_gettime(CLOCK_MONOTONIC, &start);
                started = 1;
                char src_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, sizeof(src_ip));
                printf("First packet from %s:%d\n\n", src_ip, ntohs(src_addr.sin_port));
            }
            total_recv++;
            total_bytes += ret;

            // Print every 10000 packets
            if (total_recv % 10000 == 0) {
                clock_gettime(CLOCK_MONOTONIC, &now);
                double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
                printf("\rRecv: %lu pkts | %.2f Mbps | %.2f Kpps",
                       total_recv, (total_bytes * 8.0) / elapsed / 1e6, total_recv / elapsed / 1000);
                fflush(stdout);
            }
        } else {
            usleep(100);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;

    printf("\n\n========================================\n");
    printf("              RESULTS\n");
    printf("========================================\n");
    printf("Total Packets: %lu\n", total_recv);
    printf("Total Bytes:   %lu\n", total_bytes);
    printf("Time:          %.2f sec\n", elapsed);
    printf("Rate:          %.2f Kpps\n", total_recv / elapsed / 1000);
    printf("Throughput:    %.2f Mbps\n", (total_bytes * 8.0) / elapsed / 1e6);
    printf("========================================\n");

    close(sock);
    return 0;
}
