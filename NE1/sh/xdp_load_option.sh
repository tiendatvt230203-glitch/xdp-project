#!/usr/bin/env bash

set -euo pipefail

SQL_DIR="sql_options"
if [ -f "/opt/db.env" ]; then
  . "/opt/db.env"
else
  echo "[FATAL] Env file not found: /opt/db.env" >&2
  exit 1
fi

: "${DB_HOST:?DB_HOST is required}"
: "${DB_PORT:?DB_PORT is required}"
: "${DB_USER:?DB_USER is required}"
: "${DB_NAME:?DB_NAME is required}"
: "${DB_PASS:?DB_PASS is required}"

export PGPASSWORD="$DB_PASS"

usage() {
  echo "Usage: $0 <config_id>"
  echo
  echo "  config_id: dùng theo file sql_options/<id>_*.sql"
  echo
  echo "Ví dụ:"
  echo "  $0 21  # L3 GCM 128 (ví dụ)"
}

if [ "$#" -ne 1 ]; then
  usage
  exit 1
fi

CONFIG_ID="$1"

if ! [[ "${CONFIG_ID}" =~ ^[0-9]+$ ]]; then
  echo "config_id must be a number (any integer)"
  exit 1
fi

ID_PADDED=$(printf "%02d" "${CONFIG_ID}")
SQL_FILE_GLOB="${SQL_DIR}/${ID_PADDED}_*.sql"

shopt -s nullglob
SQL_FILES=( ${SQL_FILE_GLOB} )
shopt -u nullglob

if [ "${#SQL_FILES[@]}" -eq 0 ]; then
  echo "Could not find SQL file(s) for config_id=${CONFIG_ID} in folder ${SQL_DIR}" >&2
  echo "Tried pattern: ${SQL_FILE_GLOB}" >&2
  exit 1
fi

# If there are multiple variants (repo may contain >1 file for the same ID),
# pick the first one deterministically after sorting.
IFS=$'\n' SQL_FILES_SORTED=($(printf '%s\n' "${SQL_FILES[@]}" | sort))
unset IFS
SQL_FILE="${SQL_FILES_SORTED[0]}"

if [ "${#SQL_FILES_SORTED[@]}" -gt 1 ]; then
  echo "[WARN] Multiple SQL files matched config_id=${CONFIG_ID}:" >&2
  echo "       Using: ${SQL_FILE}" >&2
  echo "       Matches: ${SQL_FILES_SORTED[*]}" >&2
fi

echo "=== XDP LOAD OPTION ==="
echo "DB user:   ${DB_USER}"
echo "DB name:   ${DB_NAME}"
echo "Host:      ${DB_HOST}"
echo "Config ID: ${CONFIG_ID}"
echo "SQL file:  ${SQL_FILE}"
echo

echo "[1/3] Import SQL for config_id=${CONFIG_ID}"
psql -v ON_ERROR_STOP=1 -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f "${SQL_FILE}"

echo "[2/3] Materialize profile/policy tables (profile-based dispatch)"
psql -v ON_ERROR_STOP=1 -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" <<SQL
BEGIN;

DO \$\$
BEGIN
    /*
     * If user already populated xdp_profile_crypto_policies for this config_id
     * (i.e. they want custom Table-2-like rules), then do not overwrite.
     */
    IF EXISTS (
        SELECT 1
        FROM xdp_profiles p
        JOIN xdp_profile_crypto_policies pc ON pc.profile_id = p.id
        WHERE p.config_id = ${CONFIG_ID}
        LIMIT 1
    ) THEN
        -- keep existing profile/policy rows
    ELSE
        -- Rebuild profiles for this config_id from the legacy tables:
        -- xdp_configs, xdp_local_configs, xdp_wan_configs, xdp_redirect_rules.
        DELETE FROM xdp_profiles WHERE config_id = ${CONFIG_ID};

        INSERT INTO xdp_profiles (
          config_id, profile_name, enabled, channel_bonding, description
        ) VALUES (
          ${CONFIG_ID}, 'profile_default', 1, 1, 'auto profile for profile-based dispatch'
        );

        -- Map locals and wans to the profile (by interface ifname)
        INSERT INTO xdp_profile_locals (profile_id, ifname)
        SELECT p.id, l.ifname
        FROM xdp_profiles p
        JOIN xdp_local_configs l ON l.config_id = p.config_id
        WHERE p.config_id = ${CONFIG_ID};

        INSERT INTO xdp_profile_wans (profile_id, ifname)
        SELECT p.id, w.ifname
        FROM xdp_profiles p
        JOIN xdp_wan_configs w ON w.config_id = p.config_id
        WHERE p.config_id = ${CONFIG_ID};

        -- Traffic rules = redirect rules for this config_id
        INSERT INTO xdp_profile_traffic_rules (profile_id, src_cidr, dst_cidr)
        SELECT p.id, r.src_cidr, r.dst_cidr
        FROM xdp_profiles p
        JOIN xdp_redirect_rules r ON r.config_id = p.config_id
        WHERE p.config_id = ${CONFIG_ID};

        -- Default crypto policies are intentionally NOT derived from xdp_configs.
        -- In the clean design, crypto behavior is driven by xdp_profile_crypto_policies.
    END IF;
END \$\$;

COMMIT;
SQL

echo "[3/3] Notify daemon to use config_id=${CONFIG_ID}"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c "SELECT pg_notify('xdp_start', '${CONFIG_ID}');"

echo
echo "Đã load option ID=${CONFIG_ID}, materialize profile/policy, và gửi NOTIFY. Kiểm tra log của daemon để xác nhận."