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

static uint32_t flow_hash_ips(uint32_t src_ip, uint32_t dst_ip) {

    uint32_t hash = src_ip ^ dst_ip;
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
        if (!entry->ip_only_key &&
            entry->key.src_ip == src_ip &&
            entry->key.dst_ip == dst_ip &&
            entry->key.src_port == src_port &&
            entry->key.dst_port == dst_port &&
            entry->key.protocol == protocol) {

            entry->last_seen = now;
            entry->byte_count += pkt_len;

            uint32_t cur_limit = 0;
            if (entry->current_wan >= 0 && entry->current_wan < ft->wan_count)
                cur_limit = ft->wan_window_sizes[entry->current_wan];


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
    entry->ip_only_key = 0;
    entry->next = ft->buckets[idx];
    ft->buckets[idx] = entry;

    wan_idx = entry->current_wan;
    pthread_mutex_unlock(&ft->locks[idx]);
    return wan_idx;
}

static int wan_allowed_pos(int wan_idx, const int *allowed_wans, int allowed_count) {
    for (int i = 0; i < allowed_count; i++) {
        if (allowed_wans[i] == wan_idx)
            return i;
    }
    return -1;
}

int flow_table_get_wan_profile(struct flow_table *ft,
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint8_t protocol, uint32_t pkt_len,
                                const int *allowed_wans, int allowed_count) {
    if (!ft || !allowed_wans || allowed_count <= 0)
        return flow_table_get_wan(ft, src_ip, dst_ip, src_port, dst_port, protocol, pkt_len);
    if (allowed_count == 1)
        return allowed_wans[0];

    (void)src_port;
    (void)dst_port;
    (void)protocol;
    uint32_t idx = flow_hash_ips(src_ip, dst_ip);
    uint64_t now = get_time_sec();

    pthread_mutex_lock(&ft->locks[idx]);

    struct flow_entry *entry = ft->buckets[idx];

    while (entry) {
        if (entry->ip_only_key &&
            entry->key.src_ip == src_ip &&
            entry->key.dst_ip == dst_ip) {

            int pos = wan_allowed_pos(entry->current_wan, allowed_wans, allowed_count);
            if (pos < 0) {

                entry->current_wan = allowed_wans[0];
                entry->byte_count = 0;
                pos = 0;
            }

            entry->last_seen = now;
            entry->byte_count += pkt_len;

            uint32_t cur_limit = 0;
            if (entry->current_wan >= 0 && entry->current_wan < ft->wan_count)
                cur_limit = ft->wan_window_sizes[entry->current_wan];


            if (cur_limit > 0 && entry->byte_count >= cur_limit) {
                entry->byte_count = 0;
                pos = wan_allowed_pos(entry->current_wan, allowed_wans, allowed_count);
                if (pos < 0) pos = 0;
                entry->current_wan = allowed_wans[(pos + 1) % allowed_count];
            }

            int wan_idx = entry->current_wan;
            pthread_mutex_unlock(&ft->locks[idx]);
            return wan_idx;
        }
        entry = entry->next;
    }

    entry = malloc(sizeof(struct flow_entry));
    if (!entry) {
        pthread_mutex_unlock(&ft->locks[idx]);
        return 0;
    }

    entry->key.src_ip = src_ip;
    entry->key.dst_ip = dst_ip;
    entry->key.src_port = 0;
    entry->key.dst_port = 0;
    entry->key.protocol = 0;
    entry->byte_count = pkt_len;
    entry->last_seen = now;
    entry->valid = 1;
    entry->ip_only_key = 1;
    entry->next = ft->buckets[idx];

    int pick = get_next_wan(allowed_count);
    if (pick < 0) pick = 0;
    entry->current_wan = allowed_wans[pick % allowed_count];

    ft->buckets[idx] = entry;
    int wan_idx = entry->current_wan;

    pthread_mutex_unlock(&ft->locks[idx]);
    return wan_idx;
}

void flow_table_add_bytes(struct flow_table *ft,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t protocol, uint32_t extra_bytes) {


    uint32_t idx_exact = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);
    uint32_t idx_ip = flow_hash_ips(src_ip, dst_ip);

    if (idx_exact == idx_ip) {
        pthread_mutex_lock(&ft->locks[idx_exact]);
        struct flow_entry *entry = ft->buckets[idx_exact];
        while (entry) {
            if (entry->ip_only_key) {
                if (entry->key.src_ip == src_ip && entry->key.dst_ip == dst_ip) {
                    entry->byte_count += extra_bytes;
                }
            } else {
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
            }
            entry = entry->next;
        }
        pthread_mutex_unlock(&ft->locks[idx_exact]);
        return;
    }


    pthread_mutex_lock(&ft->locks[idx_exact]);
    struct flow_entry *entry = ft->buckets[idx_exact];
    while (entry) {
        if (!entry->ip_only_key &&
            entry->key.src_ip == src_ip &&
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
    pthread_mutex_unlock(&ft->locks[idx_exact]);


    pthread_mutex_lock(&ft->locks[idx_ip]);
    entry = ft->buckets[idx_ip];
    while (entry) {
        if (entry->ip_only_key &&
            entry->key.src_ip == src_ip &&
            entry->key.dst_ip == dst_ip) {
            entry->byte_count += extra_bytes;
            break;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&ft->locks[idx_ip]);
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
