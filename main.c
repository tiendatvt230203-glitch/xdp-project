#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>

#include "config.h"
#include "db_config.h"
#include "forwarder.h"

#define NOTIFY_CHANNEL "xdp_start"

static int g_active_config_id = -1;

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s               # daemon mode (LISTEN %s)\n"
            "  %s -id <ID>       # load option ID into DB + notify daemon\n"
            "\n"
            "Env (DB defaults like xdp_load_option.sh if missing):\n"
            "  DB_HOST=localhost DB_PORT=5432 DB_NAME=xdpdb DB_USER=sep\n"
            "Required: DB_PASS (or provide /opt/db.env)\n"
            "Optional: SQL_DIR (default: sql_options)\n",
            prog, NOTIFY_CHANNEL, prog);
}

static const char *policy_action_name(int action) {
    switch (action) {
    case POLICY_ACTION_BYPASS: return "bypass";
    case POLICY_ACTION_ENCRYPT_L2: return "encrypt_l2";
    case POLICY_ACTION_ENCRYPT_L3: return "encrypt_l3";
    case POLICY_ACTION_ENCRYPT_L4: return "encrypt_l4";
    default: return "?";
    }
}

static const char *policy_proto_str(uint8_t proto) {
    if (proto == POLICY_PROTO_ANY)
        return "Any";
    if (proto == 6)
        return "TCP";
    if (proto == 17)
        return "UDP";
    if (proto == 1)
        return "ICMP";
    static char buf[16];
    snprintf(buf, sizeof(buf), "ip_proto=%u", (unsigned)proto);
    return buf;
}

static const char *crypto_mode_str(int mode) {
    return (mode == CRYPTO_MODE_GCM) ? "AES-GCM" : "AES-CTR";
}

static int ipv4_netmask_to_prefix(uint32_t mask_be) {
    uint32_t m = ntohl(mask_be);
    int p = 0;
    while (m & 0x80000000U) {
        p++;
        m <<= 1;
    }
    return p;
}

static void ipv4_format_cidr(char *out, size_t outsz, uint32_t net_be, uint32_t mask_be) {
    char ip[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = net_be };
    if (!inet_ntop(AF_INET, &a, ip, sizeof(ip)))
        snprintf(out, outsz, "?");
    else
        snprintf(out, outsz, "%s/%d", ip, ipv4_netmask_to_prefix(mask_be));
}

static void policy_port_str(char *out, size_t outsz, int from, int to) {
    if (from < 0 || to < 0)
        snprintf(out, outsz, "Any");
    else if (from == to)
        snprintf(out, outsz, "%d", from);
    else
        snprintf(out, outsz, "%d-%d", from, to);
}

static void policy_cidr_field(char *out, size_t outsz, int any, int negate,
                               uint32_t net_be, uint32_t mask_be) {
    if (any) {
        snprintf(out, outsz, "Any");
        return;
    }
    char cidr[48];
    ipv4_format_cidr(cidr, sizeof(cidr), net_be, mask_be);
    if (negate)
        snprintf(out, outsz, "!%s", cidr);
    else
        snprintf(out, outsz, "%s", cidr);
}

static void log_crypto_policies_human(struct app_config *cfg, int config_id) {
    fprintf(stderr,
            "[CRYPTO POLICIES] config_id=%d — xdp_profile_crypto_policies as loaded (grouped by profile)\n",
            config_id);

    if (cfg->profile_count <= 0) {
        fprintf(stderr,
                "  (no profiles; policies=%d — check xdp_profiles / DB load)\n",
                cfg->policy_count);
        for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
            const struct crypto_policy *cp = &cfg->policies[pi];
            fprintf(stderr,
                    "  [orphan POL] id=%d %s %s proto=%s prio=%d\n",
                    cp->id,
                    policy_action_name(cp->action),
                    crypto_mode_str(cp->crypto_mode),
                    policy_proto_str(cp->protocol),
                    cp->priority);
        }
        return;
    }

    for (int pr = 0; pr < cfg->profile_count; pr++) {
        struct profile_config *p = &cfg->profiles[pr];
        fprintf(stderr,
                "  [profile] id=%d name=\"%s\" enabled=%d locals=%d wans=%d traffic_rules=%d policy_refs=%d\n",
                p->id,
                p->name,
                p->enabled,
                p->local_count,
                p->wan_count,
                p->traffic_rule_count,
                p->policy_count);

        if (p->local_count > 0) {
            fprintf(stderr, "    interfaces local: ");
            for (int li = 0; li < p->local_count; li++) {
                int idx = p->local_indices[li];
                if (idx >= 0 && idx < cfg->local_count)
                    fprintf(stderr, "%s%s", li ? ", " : "", cfg->locals[idx].ifname);
            }
            fprintf(stderr, "\n");
        }
        if (p->wan_count > 0) {
            fprintf(stderr, "    interfaces wan:  ");
            for (int wi = 0; wi < p->wan_count; wi++) {
                int idx = p->wan_indices[wi];
                if (idx >= 0 && idx < cfg->wan_count)
                    fprintf(stderr, "%s%s", wi ? ", " : "", cfg->wans[idx].ifname);
            }
            fprintf(stderr, "\n");
        }

        for (int ti = 0; ti < p->traffic_rule_count; ti++) {
            struct profile_traffic_rule *tr = &p->traffic_rules[ti];
            char sbuf[64], dbuf[64];
            ipv4_format_cidr(sbuf, sizeof(sbuf), tr->src_net, tr->src_mask);
            ipv4_format_cidr(dbuf, sizeof(dbuf), tr->dst_net, tr->dst_mask);
            fprintf(stderr, "    traffic_rule[%d]: src=%s dst=%s\n", ti, sbuf, dbuf);
        }

        for (int j = 0; j < p->policy_count; j++) {
            int pix = p->policy_indices[j];
            if (pix < 0 || pix >= cfg->policy_count)
                continue;
            const struct crypto_policy *cp = &cfg->policies[pix];
            char src_c[72], dst_c[72], sp[24], dp[24];
            policy_cidr_field(src_c, sizeof(src_c), cp->src_any, cp->src_negate, cp->src_net, cp->src_mask);
            policy_cidr_field(dst_c, sizeof(dst_c), cp->dst_any, cp->dst_negate, cp->dst_net, cp->dst_mask);
            policy_port_str(sp, sizeof(sp), cp->src_port_from, cp->src_port_to);
            policy_port_str(dp, sizeof(dp), cp->dst_port_from, cp->dst_port_to);

            fprintf(stderr,
                    "    crypto_policy id=%d (row PK) priority=%d\n"
                    "      layer/action: %s  |  match: protocol=%s  src_ip=%s  dst_ip=%s  src_port=%s  dst_port=%s\n"
                    "      crypto: %s-%u  nonce=%d bytes  policy_embed_byte=0x%02x (id&0xFF on wire for L3/L4)\n"
                    "      key_prefix(hex)=%02x%02x%02x%02x (first 4 bytes)\n",
                    cp->id,
                    cp->priority,
                    policy_action_name(cp->action),
                    policy_proto_str(cp->protocol),
                    src_c,
                    dst_c,
                    sp,
                    dp,
                    crypto_mode_str(cp->crypto_mode),
                    (unsigned)cp->aes_bits,
                    cp->nonce_size,
                    (unsigned)(cp->id & 0xFF),
                    cp->key[0],
                    cp->key[1],
                    cp->key[2],
                    cp->key[3]);
        }
    }
}

static void log_wan_l2_resolution_plan(struct app_config *cfg) {
    if (!cfg) return;
    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *w = &cfg->wans[i];
        fprintf(stderr,
                "[WAN CFG] if=%s peer_dst_ip=%u (ARP->dest MAC Sep) static_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                w->ifname,
                (unsigned)ntohl(w->dst_ip),
                w->dst_mac[0], w->dst_mac[1], w->dst_mac[2],
                w->dst_mac[3], w->dst_mac[4], w->dst_mac[5]);
    }
}

static void load_env_from_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[ENV] Không mở được file env: %s\n", path);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;

        char *eq = strchr(p, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = p;
        char *val = eq + 1;

        char *end = key + strlen(key) - 1;
        while (end > key && (*end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        while (*val == ' ' || *val == '\t') val++;

        size_t len = strlen(val);
        while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '\r')) {
            val[--len] = '\0';
        }

        if (len >= 2 && val[0] == '"' && val[len - 1] == '"') {
            val[len - 1] = '\0';
            val++;
        }

        if (*key && *val) {
            setenv(key, val, 0);
        }
    }

    fclose(f);
}

static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format,
                               va_list args) {
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

static void setenv_default(const char *k, const char *v) {
    if (!k || !v) return;
    const char *cur = getenv(k);
    if (!cur || !*cur) setenv(k, v, 0);
}

static int parse_int_strict(const char *s, int *out) {
    if (!s || !*s) return -1;
    /* Match script: digits only (any integer), keep it simple */
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
    }
    long v = strtol(s, NULL, 10);
    if (v < 0 || v > INT_MAX) return -1;
    *out = (int)v;
    return 0;
}

static char *read_entire_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

static int starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int ends_with(const char *s, const char *suffix) {
    size_t sl = strlen(s), su = strlen(suffix);
    if (su > sl) return 0;
    return memcmp(s + (sl - su), suffix, su) == 0;
}

static int join_path(char *out, size_t outsz, const char *a, const char *b) {
    if (!a || !b) return -1;
    if (snprintf(out, outsz, "%s/%s", a, b) >= (int)outsz) return -1;
    return 0;
}

static int resolve_default_sql_dir(char *out, size_t outsz, const char *argv0) {
    const char *env = getenv("SQL_DIR");
    if (env && *env) {
        if (snprintf(out, outsz, "%s", env) >= (int)outsz) return -1;
        return 0;
    }

    /* Prefer ./sql_options if present. */
    struct stat st;
    if (stat("sql_options", &st) == 0 && S_ISDIR(st.st_mode)) {
        if (snprintf(out, outsz, "sql_options") >= (int)outsz) return -1;
        return 0;
    }

    /* Fallback: if binary is bin/network-encryptor, try ../sql_options. */
    char rp[PATH_MAX];
    if (argv0 && realpath(argv0, rp)) {
        char rp2[PATH_MAX];
        snprintf(rp2, sizeof(rp2), "%s", rp);
        char *d = dirname(rp2);
        char candidate[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/../sql_options", d) < (int)sizeof(candidate)) {
            if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
                if (snprintf(out, outsz, "%s", candidate) >= (int)outsz) return -1;
                return 0;
            }
        }
    }

    /* Last resort: relative name (may fail later with good error). */
    if (snprintf(out, outsz, "sql_options") >= (int)outsz) return -1;
    return 0;
}

static int find_sql_file_for_id(char *out, size_t outsz, const char *sql_dir, int config_id) {
    if (!sql_dir || !*sql_dir) return -1;
    DIR *d = opendir(sql_dir);
    if (!d) return -1;

    char idp[8];
    snprintf(idp, sizeof(idp), "%02d", config_id);
    char prefix[16];
    snprintf(prefix, sizeof(prefix), "%s_", idp);

    struct dirent *ent;
    char best[PATH_MAX] = {0};
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        if (name[0] == '.') continue;
        if (!starts_with(name, prefix)) continue;
        if (!ends_with(name, ".sql")) continue;
        /* Pick lexicographically smallest match for determinism. */
        if (!best[0] || strcmp(name, best) < 0) {
            snprintf(best, sizeof(best), "%s", name);
        }
    }
    closedir(d);

    if (!best[0]) return -1;
    return join_path(out, outsz, sql_dir, best);
}

static int exec_sql(PGconn *conn, const char *sql, const char *label) {
    if (!sql || !*sql) return 0;
    PGresult *res = PQexec(conn, sql);
    ExecStatusType st = PQresultStatus(res);
    if (!(st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK)) {
        fprintf(stderr, "[DB] %s failed: %s\n", label ? label : "SQL", PQerrorMessage(conn));
        if (res) PQclear(res);
        return -1;
    }
    if (res) PQclear(res);
    return 0;
}

static int exec_materialize_profile_policy(PGconn *conn, int config_id) {
    char sql[4096];
    int n = snprintf(
        sql, sizeof(sql),
        "BEGIN;\n"
        "DO $$\n"
        "BEGIN\n"
        "    IF EXISTS (\n"
        "        SELECT 1\n"
        "        FROM xdp_profiles p\n"
        "        JOIN xdp_profile_crypto_policies pc ON pc.profile_id = p.id\n"
        "        WHERE p.config_id = %d\n"
        "        LIMIT 1\n"
        "    ) THEN\n"
        "        -- keep existing profile/policy rows\n"
        "    ELSE\n"
        "        DELETE FROM xdp_profiles WHERE config_id = %d;\n"
        "\n"
        "        INSERT INTO xdp_profiles (\n"
        "          config_id, profile_name, enabled, channel_bonding, description\n"
        "        ) VALUES (\n"
        "          %d, 'profile_default', 1, 1, 'auto profile for profile-based dispatch'\n"
        "        );\n"
        "\n"
        "        INSERT INTO xdp_profile_locals (profile_id, ifname)\n"
        "        SELECT p.id, l.ifname\n"
        "        FROM xdp_profiles p\n"
        "        JOIN xdp_local_configs l ON l.config_id = p.config_id\n"
        "        WHERE p.config_id = %d;\n"
        "\n"
        "        INSERT INTO xdp_profile_wans (profile_id, ifname)\n"
        "        SELECT p.id, w.ifname\n"
        "        FROM xdp_profiles p\n"
        "        JOIN xdp_wan_configs w ON w.config_id = p.config_id\n"
        "        WHERE p.config_id = %d;\n"
        "\n"
        "        INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)\n"
        "        SELECT p.id, r.src_cidr, r.dst_cidr\n"
        "        FROM xdp_profiles p\n"
        "        JOIN xdp_redirect_rules r ON r.config_id = p.config_id\n"
        "        WHERE p.config_id = %d;\n"
        "\n"
        "        INSERT INTO xdp_profile_crypto_policies (\n"
        "          id,\n"
        "          profile_id,\n"
        "          priority,\n"
        "          action,\n"
        "          protocol,\n"
        "          src_cidr,\n"
        "          src_port,\n"
        "          dst_cidr,\n"
        "          dst_port,\n"
        "          crypto_mode,\n"
        "          aes_bits,\n"
        "          nonce_size,\n"
        "          crypto_key\n"
        "        )\n"
        "        SELECT\n"
        "          (100 + 256 * %d),\n"
        "          p.id,\n"
        "          100,\n"
        "          CASE\n"
        "            WHEN c.encrypt_layer = 2 THEN 'encrypt_l2'\n"
        "            WHEN c.encrypt_layer = 3 THEN 'encrypt_l3'\n"
        "            WHEN c.encrypt_layer = 4 THEN 'encrypt_l4'\n"
        "            ELSE 'bypass'\n"
        "          END,\n"
        "          'Any',\n"
        "          'Any',\n"
        "          'Any',\n"
        "          'Any',\n"
        "          'Any',\n"
        "          c.crypto_mode,\n"
        "          c.aes_bits,\n"
        "          c.nonce_size,\n"
        "          c.crypto_key\n"
        "        FROM xdp_profiles p\n"
        "        JOIN xdp_configs c ON c.id = p.config_id\n"
        "        WHERE p.config_id = %d;\n"
        "    END IF;\n"
        "END $$;\n"
        "COMMIT;\n",
        config_id, config_id, config_id,
        config_id, config_id, config_id,
        config_id, config_id);
    if (n <= 0 || (size_t)n >= sizeof(sql)) return -1;
    return exec_sql(conn, sql, "materialize profile/policy");
}

int main(int argc, char **argv) {
    if (!getenv("DB_HOST")) {
        load_env_from_file("/opt/db.env");
    }

    /* Match xdp_load_option.sh defaults when env is not provided. */
    setenv_default("DB_HOST", "localhost");
    setenv_default("DB_PORT", "5432");
    setenv_default("DB_NAME", "xdpdb");
    setenv_default("DB_USER", "sep");

    const char *db_pass = getenv("DB_PASS");
    const char *keywords[] = {"host", "port", "dbname", "user", "password", "connect_timeout", NULL};
    const char *values[]   = {getenv("DB_HOST"), getenv("DB_PORT"), getenv("DB_NAME"), 
                              getenv("DB_USER"), db_pass, "10", NULL};

    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }

    int config_id = -1;
    const char *config_id_s = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            config_id_s = argv[++i];
            if (parse_int_strict(config_id_s, &config_id) != 0) {
                fprintf(stderr, "[FATAL] config_id must be a number (digits only)\n");
                usage(argv[0]);
                return 1;
            }
        }
    }

    if (config_id >= 0) {
        if (!getenv("DB_HOST") || !getenv("DB_PORT") || !getenv("DB_NAME") || !getenv("DB_USER") || !db_pass) {
            fprintf(stderr,
                    "[FATAL] Missing DB env. Need DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASS (or provide /opt/db.env)\n");
            return 1;
        }

        char sql_dir[PATH_MAX];
        if (resolve_default_sql_dir(sql_dir, sizeof(sql_dir), argv[0]) != 0) {
            fprintf(stderr, "[FATAL] Could not resolve SQL_DIR\n");
            return 1;
        }

        char sql_file[PATH_MAX];
        if (find_sql_file_for_id(sql_file, sizeof(sql_file), sql_dir, config_id) != 0) {
            fprintf(stderr,
                    "[FATAL] Không tìm thấy file SQL cho ID=%d trong folder %s (pattern: %02d_*.sql)\n",
                    config_id, sql_dir, config_id);
            return 1;
        }

        fprintf(stderr, "[LOAD] config_id=%d sql_file=%s\n", config_id, sql_file);

        PGconn *conn = PQconnectdbParams(keywords, values, 0);
        if (PQstatus(conn) != CONNECTION_OK) {
            fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(conn));
            PQfinish(conn);
            return 1;
        }

        size_t sql_len = 0;
        char *sql_blob = read_entire_file(sql_file, &sql_len);
        if (!sql_blob) {
            fprintf(stderr, "[FATAL] Could not read SQL file: %s (errno=%d)\n", sql_file, errno);
            PQfinish(conn);
            return 1;
        }

        if (exec_sql(conn, sql_blob, "import sql_options") != 0) {
            free(sql_blob);
            PQfinish(conn);
            return 1;
        }
        free(sql_blob);

        if (exec_materialize_profile_policy(conn, config_id) != 0) {
            PQfinish(conn);
            return 1;
        }

        char idbuf[32];
        snprintf(idbuf, sizeof(idbuf), "%d", config_id);

        const char *notifyParams[2] = { NOTIFY_CHANNEL, idbuf };
        PGresult *notify_res = PQexecParams(
            conn,
            "SELECT pg_notify($1, $2);",
            2,
            NULL,
            notifyParams,
            NULL,
            NULL,
            0);
        ExecStatusType st = PQresultStatus(notify_res);
        if (!(st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK)) {
            fprintf(stderr, "[FATAL] notify failed: %s", PQerrorMessage(conn));
            if (notify_res) PQclear(notify_res);
            PQfinish(conn);
            return 1;
        }
        if (notify_res) PQclear(notify_res);
        PQfinish(conn);

        fprintf(stderr, "[OK] Loaded option ID=%d and notified channel=%s\n", config_id, NOTIFY_CHANNEL);
        return 0;
    }

    libbpf_set_print(libbpf_print_silent);
    PGconn *listen_conn = PQconnectdbParams(keywords, values, 0);
    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    while (1) {
        int pq_fd = PQsocket(listen_conn);
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pq_fd, &rfds);

        if (select(pq_fd + 1, &rfds, NULL, NULL, NULL) < 0) continue;

        PQconsumeInput(listen_conn);
        PGnotify *notify;
        while ((notify = PQnotifies(listen_conn)) != NULL) {
            int id = atoi(notify->extra);
            struct app_config cfg;

            if (g_active_config_id == -1 || g_active_config_id == id) {
                if (config_load_from_db(&cfg, id, db_pass) == 0) {
                    /* Debug: confirm DB materialization -> cfg->policy list */
                    fprintf(stderr,
                            "[DB LOAD] config_id=%d crypto_enabled=%d encrypt_layer=%d "
                            "fake_protocol=%u (global xdp_configs only) "
                            "crypto_mode=%d aes_bits=%d nonce_size=%d locals=%d wans=%d profiles=%d policies=%d\n",
                            id,
                            cfg.crypto_enabled,
                            cfg.encrypt_layer,
                            (unsigned)cfg.fake_protocol,
                            cfg.crypto_mode,
                            cfg.aes_bits,
                            cfg.nonce_size,
                            cfg.local_count,
                            cfg.wan_count,
                            cfg.profile_count,
                            cfg.policy_count);
                    log_crypto_policies_human(&cfg, id);
                    log_wan_l2_resolution_plan(&cfg);
                    struct forwarder fwd;
                    if (forwarder_init(&fwd, &cfg) == 0) {
                        g_active_config_id = id;
                        forwarder_run(&fwd);
                        forwarder_cleanup(&fwd);
                        g_active_config_id = -1;
                    } else {
                        fprintf(stderr,
                                "[FATAL] forwarder_init failed for config_id=%d — "
                                "often AF_XDP EBUSY: another XDP/AF_XDP on the local NIC, "
                                "or stale driver-mode XDP; try: ip link set dev <iface> xdp off, "
                                "bpftool net list, ensure single network-encryptor instance.\n",
                                id);
                    }
                }
            }
            PQfreemem(notify);
        }

        if (PQstatus(listen_conn) != CONNECTION_OK) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
        }
    }

    PQfinish(listen_conn);
    return 0;
}

// int main(int argc, char **argv) {
//     const char *sock_path = getenv("MWAN_SOCKET_PATH");

//     printf("--- [SYSTEM STARTUP] ---\n");
//     const char *db_host = getenv("DB_HOST");
//     const char *db_port = getenv("DB_PORT");
//     const char *db_user = getenv("DB_USER");
//     const char *db_name = getenv("DB_NAME");
//     const char *db_pass = getenv("DB_PASS");

//     if (!db_host || !db_port || !db_user || !db_name || !db_pass) {
//         load_env_from_file("/opt/db.env");
//         db_host = getenv("DB_HOST");
//         db_port = getenv("DB_PORT");
//         db_user = getenv("DB_USER");
//         db_name = getenv("DB_NAME");
//         db_pass = getenv("DB_PASS");
//     }

//     if (!db_host || !db_port || !db_user || !db_name || !db_pass) {
//         fprintf(stderr, "[FATAL] Thiếu biến môi trường DB (DB_HOST/DB_PORT/DB_USER/DB_NAME/DB_PASS)\n");
//         return 1;
//     }

//     printf("[DEBUG] DB_PASS_LEN nhận được: %zu\n", strlen(db_pass));

//     const char *keywords[] = {
//         "host", "port", "dbname", "user", "password", "connect_timeout", NULL,
//     };
//     const char *values[] = {
//         db_host, db_port, db_name, db_user, db_pass, "10", NULL,
//     };

//     int config_id = -1;
//     for (int i = 1; i < argc; i++) {
//         if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
//             config_id = atoi(argv[++i]);
//         }
//     }

//     if (config_id >= 0) {
//         PGconn *conn = PQconnectdbParams(keywords, values, 0);
//         if (PQstatus(conn) != CONNECTION_OK) {
//             fprintf(stderr,
//                     "[ERROR] CLI Connection failed: %s",
//                     PQerrorMessage(conn));
//             PQfinish(conn);
//             return 1;
//         }

//         /* Kiểm tra ID có tồn tại trong xdp_configs hay không */
//         char id_str[32];
//         snprintf(id_str, sizeof(id_str), "%d", config_id);
//         const char *params[1] = { id_str };

//         PGresult *check_res = PQexecParams(
//             conn,
//             "SELECT 1 FROM xdp_configs WHERE id = $1",
//             1,        /* nParams */
//             NULL,     /* paramTypes */
//             params,   /* paramValues */
//             NULL,     /* paramLengths */
//             NULL,     /* paramFormats */
//             0         /* resultFormat: text */
//         );

//         if (PQresultStatus(check_res) != PGRES_TUPLES_OK) {
//             fprintf(stderr,
//                     "[ERROR] CLI check ID query failed: %s",
//                     PQerrorMessage(conn));
//             PQclear(check_res);
//             PQfinish(conn);
//             return 1;
//         }

//         if (PQntuples(check_res) == 0) {
//             fprintf(stderr,
//                     "[ERROR] Config ID %d not found in xdp_configs. NOTIFY skipped.\n",
//                     config_id);
//             PQclear(check_res);
//             PQfinish(conn);
//             return 1;
//         }

//         PQclear(check_res);

//         char sql[128];
//         snprintf(sql, sizeof(sql), "NOTIFY %s, '%d';", NOTIFY_CHANNEL, config_id);
//         PQclear(PQexec(conn, sql));

//         printf("[OK] Đã gửi tín hiệu NOTIFY cho ID: %d\n", config_id);

//         PQfinish(conn);
//         return 0;
//     }

//     libbpf_set_print(libbpf_print_silent);

//     PGconn *listen_conn = PQconnectdbParams(keywords, values, 0);
//     if (PQstatus(listen_conn) != CONNECTION_OK) {
//         fprintf(stderr,
//                 "[FATAL] DB Connection failed: %s",
//                 PQerrorMessage(listen_conn));
//         PQfinish(listen_conn);
//         return 1;
//     }

//     printf("[INFO] Kết nối Database thành công: %s\n", db_name);
//     PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

//     while (1) {
//         int pq_fd = PQsocket(listen_conn);
//         fd_set rfds;

//         FD_ZERO(&rfds);
//         FD_SET(pq_fd, &rfds);

//         if (select(pq_fd + 1, &rfds, NULL, NULL, NULL) < 0) {
//             continue;
//         }

//         PQconsumeInput(listen_conn);

//         PGnotify *notify;
//         while ((notify = PQnotifies(listen_conn)) != NULL) {
//             int id = atoi(notify->extra);
//             printf("[EVENT] Nhận tín hiệu cho ID: %d\n", id);
//             PQfreemem(notify);

//             if (g_active_config_id != -1 && g_active_config_id != id) {
//                 fprintf(stderr,
//                         "[WARN] Đang chạy với config id=%d, bỏ qua yêu cầu "
//                         "chuyển sang id=%d (cần restart service để đổi option).\n",
//                         g_active_config_id,
//                         id);
//                 continue;
//             }

//             struct app_config cfg;
//             if (config_load_from_db(&cfg, id, db_pass) == 0) {
//                 printf("[CONFIG] id=%d crypto_enabled=%d encrypt_layer=%d "
//                        "crypto_mode=%d aes_bits=%d nonce_size=%d\n",
//                        id,
//                        cfg.crypto_enabled,
//                        cfg.encrypt_layer,
//                        cfg.crypto_mode,
//                        cfg.aes_bits,
//                        cfg.nonce_size);

//                 struct forwarder fwd;
//                 if (forwarder_init(&fwd, &cfg) == 0) {
//                     g_active_config_id = id;
//                     printf("[FORWARDER] Bắt đầu chạy với config id=%d\n", id);
//                     forwarder_run(&fwd);
//                     printf("[FORWARDER] Kết thúc với config id=%d\n", id);
//                     forwarder_cleanup(&fwd);
//                     g_active_config_id = -1;
//                 } else {
//                     fprintf(stderr,
//                             "[ERROR] forwarder_init failed for config id=%d\n",
//                             id);
//                 }
//             } else {
//                 fprintf(stderr,
//                         "[ERROR] config_load_from_db failed for id=%d\n",
//                         id);
//             }
//         }

//         if (PQstatus(listen_conn) != CONNECTION_OK) {
//             fprintf(stderr,
//                     "[WARN] Mất kết nối DB, đang thử lại...\n");
//             PQreset(listen_conn);
//             PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
//         }
//     }

//     PQfinish(listen_conn);
//     return 0;
// }
