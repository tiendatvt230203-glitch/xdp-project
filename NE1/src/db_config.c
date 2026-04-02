#include "../inc/db_config.h"
#include "../inc/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <strings.h>

static void db_finish(PGconn *conn, PGresult *res) {
    if (res)  PQclear(res);
    if (conn) PQfinish(conn);
}

static int str_is_any(const char *v) {
    if (!v) return 1;
    while (*v == ' ' || *v == '\t') v++;
    return (v[0] == '\0' || strcasecmp(v, "any") == 0 || strcmp(v, "*") == 0);
}

static int parse_port_range(const char *v, int *from_out, int *to_out) {
    if (str_is_any(v)) {
        *from_out = -1;
        *to_out = -1;
        return 0;
    }
    int a = -1, b = -1;
    if (sscanf(v, "%d-%d", &a, &b) == 2 && a >= 0 && b >= a && b <= 65535) {
        *from_out = a;
        *to_out = b;
        return 0;
    }
    if (sscanf(v, "%d", &a) == 1 && a >= 0 && a <= 65535) {
        *from_out = a;
        *to_out = a;
        return 0;
    }
    return -1;
}

static int parse_ipv4_addr(const char *v, uint32_t *out_ip) {
    if (!v || !out_ip || v[0] == '\0')
        return -1;
    char buf[64];
    strncpy(buf, v, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    if (slash)
        *slash = '\0';
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return -1;
    *out_ip = a.s_addr;
    return 0;
}

static uint8_t parse_protocol_name(const char *v) {
    if (str_is_any(v)) return POLICY_PROTO_ANY;
    if (strcasecmp(v, "tcp") == 0) return 6;
    if (strcasecmp(v, "udp") == 0) return 17;
    if (strcasecmp(v, "icmp") == 0) return 1;
    if (strcasecmp(v, "ospf") == 0) return 89;
    return (uint8_t)atoi(v);
}

static int parse_action_name(const char *v) {
    if (!v) return POLICY_ACTION_BYPASS;
    if (strcasecmp(v, "bypass") == 0) return POLICY_ACTION_BYPASS;
    if (strcasecmp(v, "encrypt_l2") == 0 || strcasecmp(v, "encrypt l2") == 0) return POLICY_ACTION_ENCRYPT_L2;
    if (strcasecmp(v, "encrypt_l3") == 0 || strcasecmp(v, "encrypt l3") == 0) return POLICY_ACTION_ENCRYPT_L3;
    if (strcasecmp(v, "encrypt_l4") == 0 || strcasecmp(v, "encrypt l4") == 0) return POLICY_ACTION_ENCRYPT_L4;
    return atoi(v);
}

static int parse_cidr_any_or_negated(const char *v_in, int *any_out, int *neg_out,
                                     uint32_t *net_out, uint32_t *mask_out) {
    if (!any_out || !neg_out || !net_out || !mask_out)
        return -1;

    *any_out = 1;
    *neg_out = 0;
    *net_out = 0;
    *mask_out = 0;

    if (str_is_any(v_in)) {
        *any_out = 1;
        return 0;
    }


    while (*v_in == ' ' || *v_in == '\t') v_in++;
    if (v_in[0] == '!') {
        *neg_out = 1;
        v_in++;
        while (*v_in == ' ' || *v_in == '\t') v_in++;
    }

    uint32_t ip = 0, mask = 0, net = 0;
    if (parse_ip_cidr_pub(v_in, &ip, &mask, &net) != 0) {
        return -1;
    }
    *any_out = 0;
    *net_out = net;
    *mask_out = mask;
    return 0;
}

static int find_local_index_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0) return i;
    }
    return -1;
}

static int find_wan_index_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0) return i;
    }
    return -1;
}

static void recompute_profile_ingress_aggregates(struct app_config *cfg) {
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        struct profile_config *p = &cfg->profiles[pi];
        uint64_t sum = 0;
        for (int li = 0; li < p->local_count; li++) {
            int idx = p->local_indices[li];
            if (idx >= 0 && idx < cfg->local_count)
                sum += (uint64_t)cfg->locals[idx].ingress_mbps;
        }
        p->aggregate_ingress_mbps = (sum > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)sum;
    }
}

static int load_profiles_and_policies(struct app_config *cfg, PGconn *conn, int config_id) {
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT id, profile_name, enabled, channel_bonding "
        "FROM xdp_profiles WHERE config_id = $1 ORDER BY id",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {

        PQclear(res);
        return 0;
    }

    int nprof = PQntuples(res);
    if (nprof > MAX_PROFILES) nprof = MAX_PROFILES;

    for (int i = 0; i < nprof; i++) {
        struct profile_config *p = &cfg->profiles[cfg->profile_count];
        memset(p, 0, sizeof(*p));
        p->id = atoi(PQgetvalue(res, i, 0));
        strncpy(p->name, PQgetvalue(res, i, 1), sizeof(p->name) - 1);
        p->enabled = atoi(PQgetvalue(res, i, 2));
        p->channel_bonding = atoi(PQgetvalue(res, i, 3));
        cfg->profile_count++;
    }
    PQclear(res);

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        struct profile_config *p = &cfg->profiles[pi];
        char profile_id_str[32];
        snprintf(profile_id_str, sizeof(profile_id_str), "%d", p->id);
        const char *pp[1] = { profile_id_str };

        res = PQexecParams(conn,
            "SELECT ifname FROM xdp_profile_locals WHERE profile_id = $1 ORDER BY id",
            1, NULL, pp, NULL, NULL, 0);
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            int rows = PQntuples(res);
            for (int r = 0; r < rows && p->local_count < MAX_PROFILE_INTERFACES; r++) {
                const char *ifname = PQgetvalue(res, r, 0);
                int li = find_local_index_by_ifname(cfg, ifname);
                if (li >= 0) p->local_indices[p->local_count++] = li;
            }
        }
        PQclear(res);

        res = PQexecParams(conn,
            "SELECT ifname, bandwidth_weight_percent FROM xdp_profile_wans WHERE profile_id = $1 ORDER BY id",
            1, NULL, pp, NULL, NULL, 0);
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            int wcol = PQfnumber(res, "bandwidth_weight_percent");
            int rows = PQntuples(res);
            for (int r = 0; r < rows && p->wan_count < MAX_PROFILE_INTERFACES; r++) {
                const char *ifname = PQgetvalue(res, r, 0);
                int wi = find_wan_index_by_ifname(cfg, ifname);
                if (wi >= 0) {
                    p->wan_indices[p->wan_count] = wi;
                    if (wcol >= 0)
                        p->wan_bandwidth_weight[p->wan_count] = atoi(PQgetvalue(res, r, wcol));
                    else
                        p->wan_bandwidth_weight[p->wan_count] = 0;
                    p->wan_count++;
                }
            }
        }
        PQclear(res);

        res = PQexecParams(conn,
            "SELECT src_cidr, dst_cidr FROM xdp_profile_traffic_rules WHERE profile_id = $1 ORDER BY id",
            1, NULL, pp, NULL, NULL, 0);
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            int rows = PQntuples(res);
            for (int r = 0; r < rows && p->traffic_rule_count < MAX_PROFILE_TRAFFIC_RULES; r++) {
                struct profile_traffic_rule *tr = &p->traffic_rules[p->traffic_rule_count];
                uint32_t sip = 0, smask = 0, snet = 0;
                uint32_t dip = 0, dmask = 0, dnet = 0;
                const char *src = PQgetvalue(res, r, 0);
                const char *dst = PQgetvalue(res, r, 1);
                if (parse_ip_cidr_pub(src, &sip, &smask, &snet) != 0 ||
                    parse_ip_cidr_pub(dst, &dip, &dmask, &dnet) != 0) {
                    continue;
                }
                tr->src_net = snet;
                tr->src_mask = smask;
                tr->dst_net = dnet;
                tr->dst_mask = dmask;
                p->traffic_rule_count++;
            }
        }
        PQclear(res);

        res = PQexecParams(conn,
            "SELECT id, priority, action, protocol, src_cidr, src_port, dst_cidr, dst_port, "
            "       crypto_mode, aes_bits, nonce_size, crypto_key "
            "FROM xdp_profile_crypto_policies WHERE profile_id = $1 "
            "ORDER BY priority ASC, id ASC",
            1, NULL, pp, NULL, NULL, 0);
        if (PQresultStatus(res) == PGRES_TUPLES_OK) {
            int rows = PQntuples(res);
            for (int r = 0; r < rows && cfg->policy_count < MAX_CRYPTO_POLICIES; r++) {
                if (p->policy_count >= MAX_CRYPTO_POLICIES)
                    break;
                struct crypto_policy *cp = &cfg->policies[cfg->policy_count];
                memset(cp, 0, sizeof(*cp));

                cp->id = atoi(PQgetvalue(res, r, 0));
                cp->priority = atoi(PQgetvalue(res, r, 1));
                cp->action = parse_action_name(PQgetvalue(res, r, 2));
                cp->protocol = parse_protocol_name(PQgetvalue(res, r, 3));

                const char *src_cidr = PQgetvalue(res, r, 4);
                const char *src_port = PQgetvalue(res, r, 5);
                const char *dst_cidr = PQgetvalue(res, r, 6);
                const char *dst_port = PQgetvalue(res, r, 7);
                const char *mode = PQgetvalue(res, r, 8);
                const char *bits = PQgetvalue(res, r, 9);
                const char *nonce = PQgetvalue(res, r, 10);
                const char *key_hex = PQgetvalue(res, r, 11);


                if (parse_cidr_any_or_negated(src_cidr, &cp->src_any, &cp->src_negate,
                                              &cp->src_net, &cp->src_mask) != 0) {
                    cp->src_any = 1;
                    cp->src_negate = 0;
                }
                if (parse_cidr_any_or_negated(dst_cidr, &cp->dst_any, &cp->dst_negate,
                                              &cp->dst_net, &cp->dst_mask) != 0) {
                    cp->dst_any = 1;
                    cp->dst_negate = 0;
                }

                if (parse_port_range(src_port, &cp->src_port_from, &cp->src_port_to) != 0) {
                    cp->src_port_from = -1;
                    cp->src_port_to = -1;
                }
                if (parse_port_range(dst_port, &cp->dst_port_from, &cp->dst_port_to) != 0) {
                    cp->dst_port_from = -1;
                    cp->dst_port_to = -1;
                }

                cp->crypto_mode = (mode && (strcasecmp(mode, "gcm") == 0)) ? CRYPTO_MODE_GCM : CRYPTO_MODE_CTR;
                cp->aes_bits = bits ? atoi(bits) : 128;
                cp->nonce_size = nonce ? atoi(nonce) : 12;

                if (key_hex && key_hex[0] != '\0') {
                    int key_len = (cp->aes_bits == 256) ? 32 : 16;
                    if (parse_hex_bytes_pub(key_hex, cp->key, key_len) != 0) {
                        memset(cp->key, 0, sizeof(cp->key));
                    }
                }

                p->policy_indices[p->policy_count++] = cfg->policy_count;
                cfg->policy_count++;
            }
        }
        PQclear(res);
    }

    recompute_profile_ingress_aggregates(cfg);
    return 0;
}

static int load_global_row(struct app_config *cfg, PGresult *res,
                           char *crypto_key_hex, size_t key_hex_len)
{
    const char *v;

    v = PQgetvalue(res, 0, PQfnumber(res, "crypto_enabled"));
    cfg->crypto_enabled = v ? atoi(v) : 0;

    v = PQgetvalue(res, 0, PQfnumber(res, "encrypt_layer"));
    cfg->encrypt_layer = v ? atoi(v) : 0;

    v = PQgetvalue(res, 0, PQfnumber(res, "fake_protocol"));
    cfg->fake_protocol = (uint8_t)(v ? atoi(v) : 0);

    v = PQgetvalue(res, 0, PQfnumber(res, "crypto_mode"));
    if (v && (strcmp(v, "gcm") == 0 || strcmp(v, "GCM") == 0)) {
        cfg->crypto_mode = CRYPTO_MODE_GCM;
    } else {
        cfg->crypto_mode = CRYPTO_MODE_CTR;
    }

    v = PQgetvalue(res, 0, PQfnumber(res, "aes_bits"));
    cfg->aes_bits = v ? atoi(v) : 128;
    if (cfg->aes_bits != 128 && cfg->aes_bits != 256) {
        fprintf(stderr, "[DB CRYPTO] Invalid aes_bits (expected 128 or 256)\n");
        return -1;
    }

    v = PQgetvalue(res, 0, PQfnumber(res, "nonce_size"));
    cfg->nonce_size = v ? atoi(v) : 12;
    if (cfg->nonce_size != 4 && cfg->nonce_size != 8 &&
        cfg->nonce_size != 12 && cfg->nonce_size != 16) {
        fprintf(stderr, "[DB CRYPTO] Invalid nonce_size (expected 4, 8, 12, or 16)\n");
        return -1;
    }

    v = PQgetvalue(res, 0, PQfnumber(res, "crypto_key"));
    if (v && v[0] != '\0') {
        strncpy(crypto_key_hex, v, key_hex_len - 1);
        crypto_key_hex[key_hex_len - 1] = '\0';
    }

    return 0;
}

static int load_local_rows(struct app_config *cfg, PGresult *res)
{
    int nrows = PQntuples(res);
    if (nrows == 0) {
        fprintf(stderr, "[DB] No LOCAL interface defined for this config\n");
        return -1;
    }
    if (nrows > MAX_INTERFACES) {
        fprintf(stderr, "[DB] Too many LOCAL interfaces (%d > %d)\n", nrows, MAX_INTERFACES);
        return -1;
    }

    for (int row = 0; row < nrows; row++) {
        struct local_config *loc = &cfg->locals[cfg->local_count];
        memset(loc, 0, sizeof(*loc));

        loc->frame_size  = cfg->global_frame_size;
        loc->batch_size  = cfg->global_batch_size;
        loc->umem_mb     = DEFAULT_UMEM_MB_LOCAL;
        loc->ring_size   = DEFAULT_RING_SIZE;
        loc->queue_count = DEFAULT_QUEUE_COUNT;

        const char *v;

        v = PQgetvalue(res, row, PQfnumber(res, "ifname"));
        if (!v || v[0] == '\0') {
            fprintf(stderr, "[DB LOCAL][%d] ifname not specified\n", row);
            return -1;
        }
        strncpy(loc->ifname, v, IF_NAMESIZE - 1);

        v = PQgetvalue(res, row, PQfnumber(res, "network"));
        if (v && v[0] != '\0') {
            if (parse_ip_cidr_pub(v, &loc->ip, &loc->netmask, &loc->network) != 0) {
                fprintf(stderr, "[DB LOCAL] Invalid network CIDR: %s\n", v);
                return -1;
            }
        }

        int ing_col = PQfnumber(res, "ingress_mbps");
        if (ing_col >= 0) {
            v = PQgetvalue(res, row, ing_col);
            if (v && v[0] != '\0')
                loc->ingress_mbps = (uint32_t)strtoul(v, NULL, 10);
        }

        cfg->local_count++;
    }
    return 0;
}

static int load_wan_rows(struct app_config *cfg, PGresult *res)
{
    int nrows = PQntuples(res);
    if (nrows == 0) {
        fprintf(stderr, "[DB] No WAN interface defined for this config\n");
        return -1;
    }
    if (nrows > MAX_INTERFACES) {
        fprintf(stderr, "[DB] Too many WAN interfaces (%d > %d)\n", nrows, MAX_INTERFACES);
        return -1;
    }

    for (int row = 0; row < nrows; row++) {
        struct wan_config *wan = &cfg->wans[cfg->wan_count];
        memset(wan, 0, sizeof(*wan));

        wan->frame_size   = cfg->global_frame_size;
        wan->batch_size   = cfg->global_batch_size;
        wan->window_size  = (uint32_t)(WAN_REORDER_WINDOW_KB * 1024U);
        wan->umem_mb      = DEFAULT_UMEM_MB_WAN;
        wan->ring_size    = DEFAULT_RING_SIZE_WAN;
        wan->queue_count  = DEFAULT_QUEUE_COUNT;

        const char *v;

        v = PQgetvalue(res, row, PQfnumber(res, "ifname"));
        if (!v || v[0] == '\0') {
            fprintf(stderr, "[DB WAN][%d] ifname not specified\n", row);
            return -1;
        }
        strncpy(wan->ifname, v, IF_NAMESIZE - 1);

        int dst_ip_col = PQfnumber(res, "dst_ip");
        if (dst_ip_col >= 0) {
            v = PQgetvalue(res, row, dst_ip_col);
            if (v && v[0] != '\0' && parse_ipv4_addr(v, &wan->dst_ip) != 0) {
                fprintf(stderr, "[DB WAN] Invalid dst_ip: %s\n", v);
                return -1;
            }
        }


        int src_mac_col = PQfnumber(res, "src_mac");
        int dst_mac_col = PQfnumber(res, "dst_mac");
        if (src_mac_col >= 0) {
            v = PQgetvalue(res, row, src_mac_col);
            if (v && v[0] != '\0' && parse_mac(v, wan->src_mac) != 0) {
                fprintf(stderr, "[DB WAN] Invalid src_mac: %s\n", v);
                return -1;
            }
        }
        if (dst_mac_col >= 0) {
            v = PQgetvalue(res, row, dst_mac_col);
            if (v && v[0] != '\0' && parse_mac(v, wan->dst_mac) != 0) {
                fprintf(stderr, "[DB WAN] Invalid dst_mac: %s\n", v);
                return -1;
            }
        }


        cfg->wan_count++;
    }
    return 0;
}


static int load_redirect_rules(struct app_config *cfg, PGconn *conn, int config_id)
{
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT src_cidr, dst_cidr "
        "FROM xdp_redirect_rules WHERE config_id = $1 ORDER BY id",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] Query xdp_redirect_rules failed: %s\n",
                PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    int nrows = PQntuples(res);
    cfg->redirect.src_count = 0;
    cfg->redirect.dst_count = 0;

    for (int i = 0; i < nrows; i++) {
        const char *src = PQgetvalue(res, i, 0);
        const char *dst = PQgetvalue(res, i, 1);

        uint32_t sip, smask, snet;
        uint32_t dip, dmask, dnet;

        if (parse_ip_cidr_pub(src, &sip, &smask, &snet) != 0 ||
            parse_ip_cidr_pub(dst, &dip, &dmask, &dnet) != 0) {
            fprintf(stderr, "[DB] Invalid redirect CIDR: %s -> %s\n", src, dst);
            PQclear(res);
            return -1;
        }

        if (cfg->redirect.src_count < MAX_SRC_NETS) {
            int si = cfg->redirect.src_count++;
            cfg->redirect.src_net[si]  = snet;
            cfg->redirect.src_mask[si] = smask;
        }

        if (cfg->redirect.dst_count < MAX_DST_NETS) {
            int di = cfg->redirect.dst_count++;
            cfg->redirect.dst_net[di]  = dnet;
            cfg->redirect.dst_mask[di] = dmask;
        }
    }

    PQclear(res);
    return 0;
}


int config_load_from_db(struct app_config *cfg, int config_id, const char *conn_str)
{
    (void)conn_str;

    if (!cfg) {
        fprintf(stderr, "[DB] Null pointer argument (cfg)\n");
        return -1;
    }

    const char *db_host = getenv("DB_HOST");
    const char *db_port = getenv("DB_PORT");
    const char *db_user = getenv("DB_USER");
    const char *db_name = getenv("DB_NAME");
    const char *db_pass = getenv("DB_PASS");

    if (!db_host || !db_port || !db_user || !db_name || !db_pass) {
        fprintf(stderr, "[DB] Missing DB_* environment variables in config_load_from_db\n");
        return -1;
    }

    const char *keywords[] = {
        "host", "port", "dbname", "user", "password", "connect_timeout", NULL,
    };
    const char *values[] = {
        db_host, db_port, db_name, db_user, db_pass, "10", NULL,
    };

    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->bpf_file, "bpf/xdp_redirect.o", sizeof(cfg->bpf_file) - 1);
    cfg->global_frame_size = DEFAULT_FRAME_SIZE;
    cfg->global_batch_size = DEFAULT_BATCH_SIZE;

    PGconn *conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] Connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);

    {
        const char *params[1] = { id_str };
        PGresult *res = PQexecParams(conn,
            "SELECT 1 FROM xdp_configs WHERE id = $1",
            1, NULL, params, NULL, NULL, 0);

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            fprintf(stderr, "[DB] Query xdp_configs failed: %s\n", PQerrorMessage(conn));
            db_finish(conn, res);
            return -1;
        }

        if (PQntuples(res) == 0) {
            fprintf(stderr, "[DB] Config ID %d not found in xdp_configs\n", config_id);
            db_finish(conn, res);
            return -1;
        }
        PQclear(res);
    }

    {
        const char *params[1] = { id_str };
        PGresult *res = PQexecParams(conn,
            "SELECT ifname, network, ingress_mbps "
            "FROM xdp_local_configs WHERE config_id = $1 ORDER BY id",
            1, NULL, params, NULL, NULL, 0);

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            PQclear(res);
            res = PQexecParams(conn,
                "SELECT ifname, network "
                "FROM xdp_local_configs WHERE config_id = $1 ORDER BY id",
                1, NULL, params, NULL, NULL, 0);
        }

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            fprintf(stderr, "[DB] Query xdp_local_configs failed: %s\n", PQerrorMessage(conn));
            db_finish(conn, res);
            return -1;
        }

        if (load_local_rows(cfg, res) != 0) {
            db_finish(conn, res);
            return -1;
        }
        PQclear(res);
    }

    if (load_redirect_rules(cfg, conn, config_id) != 0) {
        PQfinish(conn);
        return -1;
    }

    {
        const char *params[1] = { id_str };

        PGresult *res = PQexecParams(conn,
            "SELECT ifname, dst_ip "
            "FROM xdp_wan_configs WHERE config_id = $1 ORDER BY id",
            1, NULL, params, NULL, NULL, 0);

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            PQclear(res);
            res = PQexecParams(conn,
                "SELECT ifname, dst_ip, src_mac, dst_mac "
                "FROM xdp_wan_configs WHERE config_id = $1 ORDER BY id",
                1, NULL, params, NULL, NULL, 0);
        }

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            PQclear(res);
            res = PQexecParams(conn,
                "SELECT ifname FROM xdp_wan_configs WHERE config_id = $1 ORDER BY id",
                1, NULL, params, NULL, NULL, 0);
        }

        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            fprintf(stderr, "[DB] Query xdp_wan_configs failed: %s\n", PQerrorMessage(conn));
            db_finish(conn, res);
            return -1;
        }

        if (load_wan_rows(cfg, res) != 0) {
            db_finish(conn, res);
            return -1;
        }
        PQclear(res);
    }

    if (load_profiles_and_policies(cfg, conn, config_id) != 0) {
        PQfinish(conn);
        return -1;
    }

    PQfinish(conn);

    /*
     * Clean design: derive runtime crypto from xdp_profile_crypto_policies.
     * xdp_configs is anchor-only (config_id existence).
     */
    cfg->crypto_enabled = 0;
    cfg->encrypt_layer = 0;
    cfg->fake_protocol = 0;
    cfg->fake_ethertype_ipv4 = 0;
    cfg->fake_ethertype_ipv6 = 0;
    cfg->crypto_mode = CRYPTO_MODE_CTR;
    cfg->aes_bits = 128;
    cfg->nonce_size = 12;
    memset(cfg->crypto_key, 0, sizeof(cfg->crypto_key));

    if (cfg->policy_count > 0) {
        int has_l2 = 0, has_l3 = 0, has_l4 = 0;
        int first_key_pi = -1;

        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &cfg->policies[pi];
            if (!cp) continue;
            if (cp->action == POLICY_ACTION_ENCRYPT_L2) has_l2 = 1;
            else if (cp->action == POLICY_ACTION_ENCRYPT_L3) has_l3 = 1;
            else if (cp->action == POLICY_ACTION_ENCRYPT_L4) has_l4 = 1;

            if (cp->action != POLICY_ACTION_BYPASS) {
                int nonzero = 0;
                for (int k = 0; k < AES_KEY_LEN; k++) {
                    if (cp->key[k] != 0) { nonzero = 1; break; }
                }
                if (nonzero && first_key_pi < 0)
                    first_key_pi = pi;
            }
        }

        /*
         * Marker rules:
         * - encrypt_l2 and encrypt_l3 cannot overlap (EtherType marker vs protocol marker).
         * - encrypt_l3 and encrypt_l4 can overlap (TCP vs UDP example: different policy actions).
         */
        if (has_l2 && has_l3) {
            fprintf(stderr,
                    "[DB CRYPTO] Invalid policy set: encrypt_l2 and encrypt_l3 cannot overlap per config_id\n");
            return -1;
        }

        cfg->crypto_enabled = (has_l2 || has_l3 || has_l4) ? 1 : 0;
        if (cfg->crypto_enabled) {
            if (has_l2) cfg->encrypt_layer = 2;
            else if (has_l3) cfg->encrypt_layer = 3;
            else cfg->encrypt_layer = 4;
        }

        if (cfg->crypto_enabled) {
            if (first_key_pi < 0) {
                fprintf(stderr,
                        "[DB CRYPTO] policies request encryption but no crypto_key was provided in xdp_profile_crypto_policies\n");
                return -1;
            }
            const struct crypto_policy *cp = &cfg->policies[first_key_pi];
            cfg->crypto_mode = cp->crypto_mode;
            cfg->aes_bits = (cp->aes_bits == 256) ? 256 : 128;
            cfg->nonce_size = (cp->nonce_size > 0) ? cp->nonce_size : 12;
            memcpy(cfg->crypto_key, cp->key, sizeof(cfg->crypto_key));
        }

        /* Markers are per-encryption-layer and must not overlap. */
        if (has_l3) {
            cfg->fake_protocol = 99;
        } else if (has_l2) {
            cfg->fake_ethertype_ipv4 = 0x88b5;
            cfg->fake_ethertype_ipv6 = 0x88b6;
        }
    }

    return config_validate(cfg);
}