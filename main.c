#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
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
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0)
        return -1;
    return 0;
}

static int setup_unix_socket(const char *path) {
    if (!path || !path[0])
        return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 8) < 0) {
        close(fd);
        unlink(path);
        return -1;
    }

    chmod(path, 0660);
    return fd;
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
    const char *db_host = getenv("DB_HOST");
    const char *db_port = getenv("DB_PORT");
    const char *db_user = getenv("DB_USER");
    const char *db_name = getenv("DB_NAME");
    const char *db_pass = getenv("DB_PASS");

    const char *sock_path = getenv("MWAN_SOCKET_PATH");

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

    /* phải có đủ thông tin DB thì mới chạy */
    if (!db_host || !db_port || !db_user || !db_name || !db_pass)
        return 1;

    libbpf_set_print(libbpf_print_silent);

    /* ghép connection string cho libpq */
    char conninfo[512];
    snprintf(conninfo, sizeof(conninfo),
             "host=%s port=%s dbname=%s user=%s password=%s",
             db_host, db_port, db_name, db_user, db_pass);

    /* CLI mode: network-encryptor -id <ID>  → chỉ gửi NOTIFY cho daemon rồi thoát */
    if (config_id >= 0) {
        PGconn *conn = PQconnectdb(conninfo);
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

    if (cpu_core >= 0 && pin_to_cpu_core(cpu_core) != 0)
        return 1;
    int unix_sock_fd = setup_unix_socket(sock_path);
    (void)unix_sock_fd;

    PGconn *listen_conn = PQconnectdb(conninfo);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        PQfinish(listen_conn);
        return 1;
    }

    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    while (1) {
        int id = wait_for_notify(listen_conn);
        if (id < 0) break;

        struct app_config cfg;
        if (config_load_from_db(&cfg, id, conninfo) != 0) continue;
        if (config_validate(&cfg) != 0) continue;

        struct forwarder fwd;
        if (forwarder_init(&fwd, &cfg) != 0) continue;

        forwarder_run(&fwd);
        forwarder_cleanup(&fwd);
    }

    PQfinish(listen_conn);
    return 0;
}
