#!/usr/bin/env bash

set -euo pipefail

DB_USER="sep"
DB_NAME="xdpdb"
DB_HOST="localhost"
SQL_DIR="sql_options"

export PGPASSWORD='ttEfyMW$)}\^>D<TF|T,Qq'

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
  psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" -f "${sql_file}"
done

echo
echo "Hoàn tất import tất cả file SQL trong ${SQL_DIR}."

