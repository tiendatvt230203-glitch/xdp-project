#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/select.h>
#include <unistd.h>

#include "config.h"
#include "db_config.h"
#include "forwarder.h"
#include "main_diag.h"

#define NOTIFY_CHANNEL "xdp_start"

static int g_active_config_id = -1;

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s               # daemon mode (LISTEN %s)\n"
            "  %s -id <ID>       # notify daemon to apply config already stored in DB\n"
            "\n"
            "The backend must persist config for <ID> in PostgreSQL first.\n"
            "This process only verifies the row exists and sends pg_notify.\n"
            "\n"
            "Env: DB_* is read from the environment (optionally via /opt/db.env).\n"
            "Required: DB_PASS or PGPASSWORD (or /opt/db.env).\n",
            prog, NOTIFY_CHANNEL, prog);
}

static void load_env_from_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[ENV] Could not open env file: %s\n", path);
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

static const char *resolve_db_password(void) {
    const char *p = getenv("DB_PASS");
    if (p && *p) return p;
    p = getenv("PGPASSWORD");
    if (p && *p) return p;
    return NULL;
}

static int parse_config_id_arg(const char *s, int *out) {
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
    }
    long v = strtol(s, NULL, 10);
    if (v < 0 || v > INT_MAX) return -1;
    *out = (int)v;
    return 0;
}

int main(int argc, char **argv) {
    load_env_from_file("/opt/db.env");                  // Đọc file db.env

    const char *db_pass = resolve_db_password();        // Xử lý password
    const char *keywords[] = {"host", "port", "dbname", "user", "password", "connect_timeout", NULL};
    const char *values[]   = {getenv("DB_HOST"), getenv("DB_PORT"), getenv("DB_NAME"),
                              getenv("DB_USER"), db_pass, "10", NULL};

    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }

    // Xử lý nhận thông tin bằng -id
    int config_id = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-id") == 0 && i + 1 < argc) {
            if (parse_config_id_arg(argv[++i], &config_id) != 0) {
                fprintf(stderr, "[FATAL] config_id must be a number (digits only)\n");
                usage(argv[0]);
                return 1;
            }
        }
    }

    // Đoạn này sẽ chạy và truyền tham số 
    if (config_id >= 0) {
        if (!db_pass || !*db_pass) {            // Kiểm tra xem có lấy được mật khẩu hay không
            fprintf(stderr,
                    "[FATAL] Missing DB credentials. Set DB_PASS or PGPASSWORD (or provide /opt/db.env).\n");
            return 1;
        }

        PGconn *conn = PQconnectdbParams(keywords, values, 0);
        if (PQstatus(conn) != CONNECTION_OK) {
            fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(conn));      // Thông báo ra connect lỗi và in ra cụ thể lỗi là gì
            PQfinish(conn);
            return 1;
        }

        char id_str[32];
        snprintf(id_str, sizeof(id_str), "%d", config_id);
        const char *check_params[1] = { id_str };
        PGresult *check_res = PQexecParams(                                                 // Kiểm tra xem có cột nào chứa thông tin ID hay không
            conn,
            "SELECT 1 FROM xdp_configs WHERE id = $1::int",
            1,
            NULL,
            check_params,
            NULL,
            NULL,
            0);
        if (PQresultStatus(check_res) != PGRES_TUPLES_OK) {                     // Kiểm tra xem có lỗi cú pháp gì hay không
            //  PGRES_TUPLES_OK:    Thành công
            //  PGRES_COMMAND_OK    Thành công nhưng không có dữ liệu
            //  PGRES_FATAL_ERROR:  Thất bại (Sai tên bảng, sai cú pháp,mất kết nối)                  
            fprintf(stderr, "[FATAL] config id lookup failed: %s", PQerrorMessage(conn));   // In ra lỗi và sử dụng hàm PQerrorMessage(conn) để biết được database thông báo ra lỗi gì
            PQclear(check_res);             // Giải phóng vùng nhớ sau khi sử dụng lệnh PQexecParams                                                     
            PQfinish(conn);                 // Đóng kết nối giữa chương trình C và PostgreSQL
            return 1;
        }
        if (PQntuples(check_res) == 0) {            // Kiểm tra xem có tồn tại ID hay không
            fprintf(stderr, "[FATAL] config_id=%d not found in xdp_configs (backend must insert it first)\n",       // Lỗi không tìm thấy id
                    config_id);
            PQclear(check_res);         // Giải phóng vùng nhớ sau khi sử dụng
            PQfinish(conn);             // Ngắt kết nối giữa chương trình C và PostgreSQL
            return 1;                   
        }
        PQclear(check_res);         

        const char *notifyParams[2] = { NOTIFY_CHANNEL, id_str };
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
            fprintf(stderr, "[FATAL] pg_notify failed: %s", PQerrorMessage(conn));
            if (notify_res) PQclear(notify_res);
            PQfinish(conn);
            return 1;
        }
        if (notify_res) PQclear(notify_res);
        PQfinish(conn);

        fprintf(stderr, "[OK] Notified %s with config_id=%d\n", NOTIFY_CHANNEL, config_id);
        return 0;
    }

    if (!db_pass || !*db_pass) {
        fprintf(stderr,
                "[FATAL] Missing DB credentials. Set DB_PASS or PGPASSWORD (or /opt/db.env)\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_silent);                  // Khóa thư viện libbpf tránh in ra log quá nhiều
    PGconn *listen_conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(listen_conn));
        PQfinish(listen_conn);
        return 1;
    }
    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    for (;;) {
        int pq_fd = PQsocket(listen_conn);                  // Truy xuất FD(là một số nguyên định danh cho kết nối giữa PostgreSQL và chương trình C)
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pq_fd, &rfds);

        if (select(pq_fd + 1, &rfds, NULL, NULL, NULL) < 0)
            continue;

        PQconsumeInput(listen_conn);
        PGnotify *notify;
        while ((notify = PQnotifies(listen_conn)) != NULL) {
            int id = atoi(notify->extra);
            struct app_config cfg;

            if (g_active_config_id == -1 || g_active_config_id == id) {
                if (config_load_from_db(&cfg, id, db_pass) == 0) {
                    main_diag_log_loaded_config(&cfg, id);
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
}
// 1. Các loại gói tin phổ biến
// Nếu trong inBuffer của bạn lúc đó không phải là thông báo, nó có thể là:
// 'C' (Command Complete): Phản hồi khi một câu lệnh SQL (như INSERT, UPDATE) chạy xong.
// 'D' (Data Row): Chứa dữ liệu của một hàng kết quả khi bạn SELECT.
// 'E' (Error Response): Thông báo lỗi từ database (ví dụ: sai cú pháp SQL).
// 'S' (Parameter Status): Thông báo thay đổi cài đặt hệ thống (ví dụ: thay đổi timezone).
// 'Z' (Ready For Query): Báo hiệu Backend đã xử lý xong và sẵn sàng nhận lệnh mới.