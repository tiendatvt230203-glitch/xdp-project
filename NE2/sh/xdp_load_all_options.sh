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

echo "=== XDP LOAD ALL OPTIONS ==="
echo "DB user: ${DB_USER}"
echo "DB name: ${DB_NAME}"
echo "Host:    ${DB_HOST}"
echo "Dir:     ${SQL_DIR}"
echo

if [ ! -d "${SQL_DIR}" ]; then
  echo "Thư mục ${SQL_DIR} không tồn tại."
  exit 1
fi

shopt -s nullglob
SQL_FILES=("${SQL_DIR}"/*.sql)
shopt -u nullglob

if [ "${#SQL_FILES[@]}" -eq 0 ]; then
  echo "Không tìm thấy file .sql nào trong ${SQL_DIR}"
  exit 1
fi

for sql_file in "${SQL_FILES[@]}"; do
  echo ">>> Import ${sql_file}"
  psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f "${sql_file}"
done

echo
echo "Hoàn tất import tất cả file SQL trong ${SQL_DIR}."