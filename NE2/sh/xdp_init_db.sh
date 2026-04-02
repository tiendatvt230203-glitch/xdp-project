#!/usr/bin/env bash

set -euo pipefail

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

echo "=== XDP DB INIT ==="
echo "User:    ${DB_USER}"
echo "DB name: ${DB_NAME}"
echo "Host:    ${DB_HOST}"
echo

echo "[1/3] Drop database if exists: ${DB_NAME}"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -c "DROP DATABASE IF EXISTS ${DB_NAME};"

echo "[2/3] Create database: ${DB_NAME}"
createdb -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" "${DB_NAME}"

echo "[3/3] Create tables from schema.sql"
psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -f schema.sql

echo
echo "Done. Database ${DB_NAME} is clean and has tables ready."