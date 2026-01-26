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

// MAXIMUM BUFFER SETTINGS for 2.5Gbps
#define FRAME_SIZE      4096                    // 4KB per frame (default)
#define FRAME_COUNT     (64 * 1024)             // 64K frames
#define UMEM_SIZE       (FRAME_COUNT * FRAME_SIZE)  // 256MB UMEM per interface
#define BATCH_SIZE      512                     // Large batch
#define RING_SIZE       16384                   // 16K ring entries

// Multi-queue support
#define MAX_QUEUES      64                      // Max RX queues per interface

// XDP flags
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif

#ifndef XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1U << 0)
#endif

#endif
