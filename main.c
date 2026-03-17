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

#include "config.h"
#include "db_config.h"
#include "forwarder.h"

#define NOTIFY_CHANNEL "xdp_start"

static int g_active_config_id = -1;

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

int main(int argc, char **argv) {
    const char *sock_path = getenv("MWAN_SOCKET_PATH");

    printf("--- [SYSTEM STARTUP] ---\n");
    const char *db_host = getenv("DB_HOST");
    const char *db_port = getenv("DB_PORT");
    const char *db_user = getenv("DB_USER");
    const char *db_name = getenv("DB_NAME");
    const char *db_pass = getenv("DB_PASS");

    if (!db_host || !db_port || !db_user || !db_name || !db_pass) {
        load_env_from_file("/opt/db.env");
        db_host = getenv("DB_HOST");
        db_port = getenv("DB_PORT");
        db_user = getenv("DB_USER");
        db_name = getenv("DB_NAME");
        db_pass = getenv("DB_PASS");
    }

    if (!db_host || !db_port || !db_user || !db_name || !db_pass) {
        fprintf(stderr, "[FATAL] Thiếu biến môi trường DB (DB_HOST/DB_PORT/DB_USER/DB_NAME/DB_PASS)\n");
        return 1;
    }

    printf("[DEBUG] DB_PASS_LEN nhận được: %zu\n", strlen(db_pass));

    const char *keywords[] = {
        "host", "port", "dbname", "user", "password", "connect_timeout", NULL,
    };
    const char *values[] = {
        db_host, db_port, db_name, db_user, db_pass, "10", NULL,
    };

    int config_id = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            config_id = atoi(argv[++i]);
        }
    }

    if (config_id >= 0) {
        PGconn *conn = PQconnectdbParams(keywords, values, 0);
        if (PQstatus(conn) != CONNECTION_OK) {
            fprintf(stderr,
                    "[ERROR] CLI Connection failed: %s",
                    PQerrorMessage(conn));
            PQfinish(conn);
            return 1;
        }

        /* Kiểm tra ID có tồn tại trong xdp_configs hay không */
        char id_str[32];
        snprintf(id_str, sizeof(id_str), "%d", config_id);
        const char *params[1] = { id_str };

        PGresult *check_res = PQexecParams(
            conn,
            "SELECT 1 FROM xdp_configs WHERE id = $1",
            1,        /* nParams */
            NULL,     /* paramTypes */
            params,   /* paramValues */
            NULL,     /* paramLengths */
            NULL,     /* paramFormats */
            0         /* resultFormat: text */
        );

        if (PQresultStatus(check_res) != PGRES_TUPLES_OK) {
            fprintf(stderr,
                    "[ERROR] CLI check ID query failed: %s",
                    PQerrorMessage(conn));
            PQclear(check_res);
            PQfinish(conn);
            return 1;
        }

        if (PQntuples(check_res) == 0) {
            fprintf(stderr,
                    "[ERROR] Config ID %d not found in xdp_configs. NOTIFY skipped.\n",
                    config_id);
            PQclear(check_res);
            PQfinish(conn);
            return 1;
        }

        PQclear(check_res);

        char sql[128];
        snprintf(sql, sizeof(sql), "NOTIFY %s, '%d';", NOTIFY_CHANNEL, config_id);
        PQclear(PQexec(conn, sql));

        printf("[OK] Đã gửi tín hiệu NOTIFY cho ID: %d\n", config_id);

        PQfinish(conn);
        return 0;
    }

    libbpf_set_print(libbpf_print_silent);

    PGconn *listen_conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        fprintf(stderr,
                "[FATAL] DB Connection failed: %s",
                PQerrorMessage(listen_conn));
        PQfinish(listen_conn);
        return 1;
    }

    printf("[INFO] Kết nối Database thành công: %s\n", db_name);
    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    while (1) {
        int pq_fd = PQsocket(listen_conn);
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(pq_fd, &rfds);

        if (select(pq_fd + 1, &rfds, NULL, NULL, NULL) < 0) {
            continue;
        }

        PQconsumeInput(listen_conn);

        PGnotify *notify;
        while ((notify = PQnotifies(listen_conn)) != NULL) {
            int id = atoi(notify->extra);
            printf("[EVENT] Nhận tín hiệu cho ID: %d\n", id);
            PQfreemem(notify);

            if (g_active_config_id != -1 && g_active_config_id != id) {
                fprintf(stderr,
                        "[WARN] Đang chạy với config id=%d, bỏ qua yêu cầu "
                        "chuyển sang id=%d (cần restart service để đổi option).\n",
                        g_active_config_id,
                        id);
                continue;
            }

            struct app_config cfg;
            if (config_load_from_db(&cfg, id, db_pass) == 0) {
                printf("[CONFIG] id=%d crypto_enabled=%d encrypt_layer=%d "
                       "crypto_mode=%d aes_bits=%d nonce_size=%d\n",
                       id,
                       cfg.crypto_enabled,
                       cfg.encrypt_layer,
                       cfg.crypto_mode,
                       cfg.aes_bits,
                       cfg.nonce_size);

                struct forwarder fwd;
                if (forwarder_init(&fwd, &cfg) == 0) {
                    g_active_config_id = id;
                    printf("[FORWARDER] Bắt đầu chạy với config id=%d\n", id);
                    forwarder_run(&fwd);
                    printf("[FORWARDER] Kết thúc với config id=%d\n", id);
                    forwarder_cleanup(&fwd);
                    g_active_config_id = -1;
                } else {
                    fprintf(stderr,
                            "[ERROR] forwarder_init failed for config id=%d\n",
                            id);
                }
            } else {
                fprintf(stderr,
                        "[ERROR] config_load_from_db failed for id=%d\n",
                        id);
            }
        }

        if (PQstatus(listen_conn) != CONNECTION_OK) {
            fprintf(stderr,
                    "[WARN] Mất kết nối DB, đang thử lại...\n");
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
        }
    }

    PQfinish(listen_conn);
    return 0;
}
