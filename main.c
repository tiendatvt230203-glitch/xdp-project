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
    printf("Usage: %s --db-url <connection_string> [--cpu-core <N>]\n", prog);
    printf("\n");
    printf("  --db-url <str>   libpq connection string\n");
    printf("  --cpu-core <N>   pin daemon process to core N\n");
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
    printf("[DAEMON] Waiting for notification on channel '" NOTIFY_CHANNEL "'...\n");
    fflush(stdout);

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
    const char *db_url = NULL;
    int cpu_core = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--db-url") == 0) {
            if (i + 1 < argc) db_url = argv[++i];
        } else if (strcmp(argv[i], "--cpu-core") == 0) {
            if (i + 1 < argc) cpu_core = atoi(argv[++i]);
        }
    }

    if (!db_url) return 1;

    libbpf_set_print(libbpf_print_silent);

    PGconn *listen_conn = PQconnectdb(db_url);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        PQfinish(listen_conn);
        return 1;
    }

    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    while (1) {
        int config_id = wait_for_notify(listen_conn);
        if (config_id < 0) break;

        struct app_config cfg;
        if (config_load_from_db(&cfg, config_id, db_url) != 0) continue;

        struct forwarder fwd;
        if (forwarder_init(&fwd, &cfg) != 0) continue;

        forwarder_run(&fwd);
        forwarder_cleanup(&fwd);
    }

    PQfinish(listen_conn);
    return 0;
}
