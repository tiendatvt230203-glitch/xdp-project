#define _POSIX_C_SOURCE 199309L
#include "../inc/flow_table.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint32_t flow_hash(uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol) {
    uint32_t hash = src_ip ^ dst_ip;
    hash ^= ((uint32_t)src_port << 16) | dst_port;
    hash ^= protocol;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6b;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35;
    hash ^= (hash >> 16);
    return hash % FLOW_TABLE_SIZE;
}

static uint64_t get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

void flow_table_init(struct flow_table *ft, const uint32_t *wan_window_sizes, int wan_count) {
    memset(ft, 0, sizeof(*ft));
    ft->wan_count = wan_count;
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (wan_window_sizes)
            ft->wan_window_sizes[i] = wan_window_sizes[i];
        else
            ft->wan_window_sizes[i] = 0;
    }
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        pthread_mutex_init(&ft->locks[i], NULL);
    }
}

void flow_table_cleanup(struct flow_table *ft) {
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        pthread_mutex_lock(&ft->locks[i]);
        struct flow_entry *entry = ft->buckets[i];
        while (entry) {
            struct flow_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        ft->buckets[i] = NULL;
        pthread_mutex_unlock(&ft->locks[i]);
        pthread_mutex_destroy(&ft->locks[i]);
    }
}

static int next_wan = 0;

static int get_next_wan(int wan_count) {
    if (wan_count <= 0)
        return 0;

    int wan = __sync_fetch_and_add(&next_wan, 1);
    if (wan < 0)
        wan = -wan;
    wan %= wan_count;
    return wan;
}

int flow_table_get_wan(struct flow_table *ft,
                       uint32_t src_ip, uint32_t dst_ip,
                       uint16_t src_port, uint16_t dst_port,
                       uint8_t protocol, uint32_t pkt_len) {
    uint32_t idx = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);
    uint64_t now = get_time_sec();
    int wan_idx;

    pthread_mutex_lock(&ft->locks[idx]);

    struct flow_entry *entry = ft->buckets[idx];
    struct flow_entry *prev = NULL;

    while (entry) {
        if (entry->key.src_ip == src_ip &&
            entry->key.dst_ip == dst_ip &&
            entry->key.src_port == src_port &&
            entry->key.dst_port == dst_port &&
            entry->key.protocol == protocol) {

            entry->last_seen = now;
            entry->byte_count += pkt_len;

            uint32_t cur_limit = 0;
            if (entry->current_wan >= 0 && entry->current_wan < ft->wan_count)
                cur_limit = ft->wan_window_sizes[entry->current_wan];

            /* If this flow reached the WAN quota, rotate to next WAN. */
            if (cur_limit > 0 && entry->byte_count >= cur_limit) {
                entry->byte_count = 0;
                entry->current_wan = (entry->current_wan + 1) % ft->wan_count;
            }

            wan_idx = entry->current_wan;
            pthread_mutex_unlock(&ft->locks[idx]);
            return wan_idx;
        }
        prev = entry;
        entry = entry->next;
    }

    entry = malloc(sizeof(struct flow_entry));
    if (!entry) {
        pthread_mutex_unlock(&ft->locks[idx]);
        return 0;
    }

    entry->key.src_ip = src_ip;
    entry->key.dst_ip = dst_ip;
    entry->key.src_port = src_port;
    entry->key.dst_port = dst_port;
    entry->key.protocol = protocol;
    entry->byte_count = pkt_len;
    entry->current_wan = get_next_wan(ft->wan_count);
    entry->last_seen = now;
    entry->valid = 1;
    entry->next = ft->buckets[idx];
    ft->buckets[idx] = entry;

    wan_idx = entry->current_wan;
    pthread_mutex_unlock(&ft->locks[idx]);
    return wan_idx;
}

void flow_table_add_bytes(struct flow_table *ft,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol, uint32_t extra_bytes) {
    uint32_t idx = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);

    pthread_mutex_lock(&ft->locks[idx]);

    struct flow_entry *entry = ft->buckets[idx];
    while (entry) {
        if (entry->key.src_ip == src_ip &&
            entry->key.dst_ip == dst_ip &&
            entry->key.src_port == src_port &&
            entry->key.dst_port == dst_port &&
            entry->key.protocol == protocol) {

            entry->byte_count += extra_bytes;

            uint32_t cur_limit = 0;
            if (entry->current_wan >= 0 && entry->current_wan < ft->wan_count)
                cur_limit = ft->wan_window_sizes[entry->current_wan];

            if (cur_limit > 0 && entry->byte_count >= cur_limit) {
                entry->byte_count = 0;
                entry->current_wan = (entry->current_wan + 1) % ft->wan_count;
            }
            break;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&ft->locks[idx]);
}

void flow_table_gc(struct flow_table *ft) {
    uint64_t now = get_time_sec();

    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        pthread_mutex_lock(&ft->locks[i]);

        struct flow_entry **pp = &ft->buckets[i];
        while (*pp) {
            struct flow_entry *entry = *pp;
            if (now - entry->last_seen > FLOW_TIMEOUT_SEC) {
                *pp = entry->next;
                free(entry);
            } else {
                pp = &entry->next;
            }
        }

        pthread_mutex_unlock(&ft->locks[i]);
    }
}
