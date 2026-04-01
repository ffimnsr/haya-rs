#!/bin/sh
# Run haya-rs migrations inside the Postgres container on first start.
# Executed by docker-entrypoint after the cluster is initialised.
# Only the UP section (between -- !UP and -- !DOWN) of each migration is run.

set -e

MIGRATIONS_DIR="/docker-entrypoint-initdb.d/migrations"

for f in "$MIGRATIONS_DIR"/*.sql; do
  [ -e "$f" ] || continue
  echo "Applying migration: $f"
  # Extract lines between -- !UP and -- !DOWN (exclusive)
  awk '/^-- !UP/{found=1; next} /^-- !DOWN/{found=0} found' "$f" \
    | psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"
done
