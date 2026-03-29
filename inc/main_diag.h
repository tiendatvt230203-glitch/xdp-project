#ifndef MAIN_DIAG_H
#define MAIN_DIAG_H

struct app_config;

/* Verbose stderr dump after config_load_from_db (daemon path). */
void main_diag_log_loaded_config(struct app_config *cfg, int config_id);

#endif
