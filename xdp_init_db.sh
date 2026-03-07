#!/usr/bin/env bash

set -euo pipefail

DB_USER="sep"
DB_NAME="xdpdb"
DB_HOST="localhost"
export PGPASSWORD='ttEfyMW$)}\^>D<TF|T,Qq'

echo "=== XDP DB INIT ==="
echo "User:    ${DB_USER}"
echo "DB name: ${DB_NAME}"
echo "Host:    ${DB_HOST}"
echo

echo "[1/3] Drop database if exists: ${DB_NAME}"
psql -h "${DB_HOST}" -U "${DB_USER}" -d postgres -c "DROP DATABASE IF EXISTS ${DB_NAME};"

echo "[2/3] Create database: ${DB_NAME}"
createdb -h "${DB_HOST}" -U "${DB_USER}" "${DB_NAME}"

echo "[3/3] Create tables from schema.sql"
psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" -f schema.sql

echo
echo "Done. Database ${DB_NAME} is clean and has tables ready."


