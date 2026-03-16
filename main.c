#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include "config.h"
#include "db_config.h"
#include "forwarder.h"

static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format, va_list args) {
    (void)level; (void)format; (void)args;
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s -id <CONFIG_ID> [--cpu-core <N>]\n",
            prog);
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

    if (!db_url || config_id < 0)
        return 1;

    libbpf_set_print(libbpf_print_silent);

    if (cpu_core >= 0 && pin_to_cpu_core(cpu_core) != 0)
        return 1;

    PGconn *conn = PQconnectdb(db_url);
    if (PQstatus(conn) != CONNECTION_OK) {
        PQfinish(conn);
        return 1;
    }

    struct app_config cfg;
    if (config_load_from_db(&cfg, config_id, db_url) != 0) {
        PQfinish(conn);
        return 1;
    }
    PQfinish(conn);

    if (config_validate(&cfg) != 0)
        return 1;

    struct forwarder fwd;
    if (forwarder_init(&fwd, &cfg) != 0)
        return 1;

    forwarder_run(&fwd);
    forwarder_cleanup(&fwd);
    return 0;
}
