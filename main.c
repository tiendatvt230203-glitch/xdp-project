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
    printf("  --db-url <str>   libpq connection string, e.g.:\n");
    printf("                     \"host=localhost user=postgres password=secret dbname=xdpdb\"\n");
    printf("                     \"postgresql://postgres:secret@localhost/xdpdb\"\n");
    printf("  --cpu-core <N>   pin entire process to CPU core N (default: 0).\n");
    printf("                   Use a single core to avoid migration and reduce packet drops.\n");
    printf("\n");
    printf("The daemon listens on PostgreSQL channel: " NOTIFY_CHANNEL "\n");
    printf("To start the forwarder, run this SQL from any client (e.g. VSCode):\n");
    printf("  SELECT pg_notify('" NOTIFY_CHANNEL "', '<config_id>');\n");
    printf("  Example: SELECT pg_notify('" NOTIFY_CHANNEL "', '1');\n");
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
    printf("[DAEMON] Send from PostgreSQL: SELECT pg_notify('" NOTIFY_CHANNEL "', '<config_id>');\n");
    fflush(stdout);

    int pq_fd = PQsocket(conn);
    if (pq_fd < 0) {
        fprintf(stderr, "[DAEMON] Invalid socket\n");
        return -1;
    }

    while (1) {
        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(pq_fd, &input_mask);

        int ret = select(pq_fd + 1, &input_mask, NULL, NULL, NULL);
        if (ret < 0) {
            perror("[DAEMON] select");
            return -1;
        }

        if (PQconsumeInput(conn) == 0) {
            fprintf(stderr, "[DAEMON] PQconsumeInput failed: %s\n", PQerrorMessage(conn));
            return -1;
        }

        PGnotify *notify = PQnotifies(conn);
        if (notify) {
            printf("[DAEMON] Received NOTIFY on channel '%s', payload: '%s'\n",
                   notify->relname, notify->extra);

            int config_id = atoi(notify->extra);
            PQfreemem(notify);

            if (config_id <= 0) {
                fprintf(stderr, "[DAEMON] Invalid config_id '%s', must be a positive integer\n",
                        notify->extra);
                continue;
            }

            return config_id;
        }
    }
}

int main(int argc, char **argv) {
    const char *db_url = NULL;
    int cpu_core = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--db-url") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --db-url requires a value\n");
                print_usage(argv[0]);
                return 1;
            }
            db_url = argv[++i];
        } else if (strcmp(argv[i], "--cpu-core") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --cpu-core requires a value\n");
                print_usage(argv[0]);
                return 1;
            }
            cpu_core = atoi(argv[++i]);
            if (cpu_core < 0) {
                fprintf(stderr, "Error: --cpu-core must be >= 0 (got %d)\n", cpu_core);
                return 1;
            }
        } else {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!db_url) {
        fprintf(stderr, "Error: --db-url is required\n");
        print_usage(argv[0]);
        return 1;
    }

    /* NOTE:
     * Previously we pinned the entire process to a single CPU core here.
     * That prevented the per-thread affinity in the forwarder from using
     * multiple cores for packet processing. We now rely on per-thread
     * pinning in the forwarder and allow the OS to schedule this daemon
     * across all available cores.
     */

    libbpf_set_print(libbpf_print_silent);

    printf("[DAEMON] Connecting to PostgreSQL...\n");
    PGconn *listen_conn = PQconnectdb(db_url);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        fprintf(stderr, "[DAEMON] Connection failed: %s\n", PQerrorMessage(listen_conn));
        PQfinish(listen_conn);
        return 1;
    }
    printf("[DAEMON] Connected.\n");

    PGresult *res = PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[DAEMON] LISTEN failed: %s\n", PQerrorMessage(listen_conn));
        PQclear(res);
        PQfinish(listen_conn);
        return 1;
    }
    PQclear(res);

    printf("[DAEMON] Ready. Listening on channel '" NOTIFY_CHANNEL "'.\n");
    printf("[DAEMON] To start XDP forwarder, run in PostgreSQL:\n");
    printf("[DAEMON]   SELECT pg_notify('" NOTIFY_CHANNEL "', '1');\n\n");
    fflush(stdout);

    while (1) {
        int config_id = wait_for_notify(listen_conn);
        if (config_id < 0) {
            fprintf(stderr, "[DAEMON] Error receiving notification. Exiting.\n");
            break;
        }

        printf("[DAEMON] Starting XDP forwarder with config ID=%d...\n", config_id);
        fflush(stdout);

        struct app_config cfg;
        if (config_load_from_db(&cfg, config_id, db_url) != 0) {
            fprintf(stderr, "[DAEMON] Failed to load config ID=%d. Waiting for next notification...\n",
                    config_id);
            continue;
        }

        printf("[DAEMON] Config loaded: LOCAL=%d WAN=%d crypto=%s\n",
               cfg.local_count, cfg.wan_count,
               cfg.crypto_enabled ? "enabled" : "disabled");

        struct forwarder fwd;
        if (forwarder_init(&fwd, &cfg) != 0) {
            fprintf(stderr, "[DAEMON] Failed to initialize forwarder. Waiting for next notification...\n");
            continue;
        }

        printf("[DAEMON] Forwarder running...\n");
        fflush(stdout);

        forwarder_run(&fwd);

        /* Print drop statistics (including WAN->LOCAL reasons) before cleanup */
        forwarder_print_stats(&fwd);

        forwarder_cleanup(&fwd);

        printf("[DAEMON] Forwarder stopped. Waiting for next notification...\n\n");
        fflush(stdout);
    }

    PQfinish(listen_conn);
    return 0;
}