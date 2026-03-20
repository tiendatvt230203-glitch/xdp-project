#include "../inc/db_config.h"
#include "../inc/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <libpq-fe.h>

static void db_finish(PGconn *conn, PGresult *res) {
    if (res)  PQclear(res);
    if (conn) PQfinish(conn);
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
        wan->window_size  = (uint32_t)(DEFAULT_WINDOW_KB * 1024);
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

    char crypto_key_hex[128] = {0};
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", config_id);

    {
        const char *params[1] = { id_str };
        PGresult *res = PQexecParams(conn,
            "SELECT crypto_enabled, crypto_key, encrypt_layer, "
            "       fake_protocol, crypto_mode, aes_bits, nonce_size "
            "FROM xdp_configs WHERE id = $1",
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

        if (load_global_row(cfg, res, crypto_key_hex, sizeof(crypto_key_hex)) != 0) {
            db_finish(conn, res);
            return -1;
        }
        PQclear(res);
    }

    {
        const char *params[1] = { id_str };
        PGresult *res = PQexecParams(conn,
            "SELECT ifname, network "
            "FROM xdp_local_configs WHERE config_id = $1 ORDER BY id",
            1, NULL, params, NULL, NULL, 0);

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
            "SELECT ifname "
            "FROM xdp_wan_configs WHERE config_id = $1 ORDER BY id",
            1, NULL, params, NULL, NULL, 0);

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

    PQfinish(conn);

    if (cfg->nonce_size == 0) cfg->nonce_size = 12;
    if (cfg->aes_bits   == 0) cfg->aes_bits   = 128;

    if (cfg->crypto_enabled && crypto_key_hex[0] != '\0') {
        int key_len = (cfg->aes_bits == 256) ? 32 : 16;
        if (parse_hex_bytes_pub(crypto_key_hex, cfg->crypto_key, key_len) != 0) {
            fprintf(stderr, "[DB CRYPTO] Invalid key (expected %d hex chars for AES-%d)\n",
                    key_len * 2, cfg->aes_bits);
            return -1;
        }
    } else if (cfg->crypto_enabled && crypto_key_hex[0] == '\0') {
        fprintf(stderr, "[DB CRYPTO] key not specified\n");
        return -1;
    }

    if (cfg->crypto_enabled) {
        if (cfg->encrypt_layer != 2 && cfg->encrypt_layer != 3 && cfg->encrypt_layer != 4) {
            fprintf(stderr, "[DB CRYPTO] encrypt_layer must be 2, 3, or 4 (got %d)\n",
                    cfg->encrypt_layer);
            return -1;
        }
        if (cfg->encrypt_layer == 2) {
            if (cfg->fake_ethertype_ipv4 == 0 && cfg->fake_ethertype_ipv6 == 0) {
                cfg->fake_ethertype_ipv4 = 0x88b5;
                cfg->fake_ethertype_ipv6 = 0x88b6;
            }
        } else if (cfg->encrypt_layer == 3) {
            if (cfg->fake_protocol == 0)
                cfg->fake_protocol = 99;
        }
    }
    return config_validate(cfg);
}
