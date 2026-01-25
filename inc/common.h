#ifndef COMMON_H
#define COMMON_H

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <errno.h>

// High-performance settings for 2.5Gbps+
#define FRAME_SIZE      2048                    // Smaller frame for better cache
#define FRAME_COUNT     (32 * 1024)             // 32K frames = 64MB UMEM
#define UMEM_SIZE       (FRAME_COUNT * FRAME_SIZE)
#define BATCH_SIZE      256                     // Large batch for throughput
#define RING_SIZE       8192                    // Large rings

// XDP flags
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif

#ifndef XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1U << 0)
#endif

#endif
