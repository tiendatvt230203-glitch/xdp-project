#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sched.h>
#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include "config.h"
#include "db_config.h"
#include "forwarder.h"

#define NOTIFY_CHANNEL "xdp_start"

static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format, va_list args) {
    (void)level; (void)format; (void)args;
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s            (daemon mode, waits for config)\n"
            "  %s -id <ID>   (notify daemon to use config ID)\n",
            prog, prog);
}

static int pin_to_cpu_core(int cpu_core) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_core, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        perror("[DAEMON] sched_setaffinity");
        return -1;
    }
    return 0;
}

static int wait_for_notify(PGconn *conn) {
    int pq_fd = PQsocket(conn);
    if (pq_fd < 0) return -1;

    while (1) {
        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(pq_fd, &input_mask);

        int ret = select(pq_fd + 1, &input_mask, NULL, NULL, NULL);
        if (ret < 0) return -1;

        if (PQconsumeInput(conn) == 0) return -1;

        PGnotify *notify = PQnotifies(conn);
        if (notify) {
            int config_id = atoi(notify->extra);
            PQfreemem(notify);
            return config_id;
        }
    }
}

int main(int argc, char **argv) {
    const char *db_url = getenv("DB_URL");
    int cpu_core = -1;
    int config_id = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--cpu-core") == 0) {
            if (i + 1 < argc) cpu_core = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-id") == 0) {
            if (i + 1 < argc) config_id = atoi(argv[++i]);
        }
    }

    if (!db_url)
        return 1;

    libbpf_set_print(libbpf_print_silent);

    /* CLI mode: network-encryp -id <ID>  → chỉ gửi NOTIFY cho daemon rồi thoát */
    if (config_id >= 0) {
        PGconn *conn = PQconnectdb(db_url);
        if (PQstatus(conn) != CONNECTION_OK) {
            PQfinish(conn);
            return 1;
        }

        char sql[128];
        snprintf(sql, sizeof(sql), "NOTIFY %s, '%d';", NOTIFY_CHANNEL, config_id);
        PGresult *res = PQexec(conn, sql);
        PQclear(res);
        PQfinish(conn);
        return 0;
    }

    /* Daemon mode: systemctl start → chờ NOTIFY để chạy theo config */
    if (cpu_core >= 0 && pin_to_cpu_core(cpu_core) != 0)
        return 1;

    PGconn *listen_conn = PQconnectdb(db_url);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        PQfinish(listen_conn);
        return 1;
    }

    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    while (1) {
        int id = wait_for_notify(listen_conn);
        if (id < 0) break;

        struct app_config cfg;
        if (config_load_from_db(&cfg, id, db_url) != 0) continue;
        if (config_validate(&cfg) != 0) continue;

        struct forwarder fwd;
        if (forwarder_init(&fwd, &cfg) != 0) continue;

        forwarder_run(&fwd);
        forwarder_cleanup(&fwd);
    }

    PQfinish(listen_conn);
    return 0;
}
