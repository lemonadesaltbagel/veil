#!/usr/bin/env bash
# Local test databases for tests/test_sources.py (all bound to 127.0.0.1, data in .run/ or a container).
#   scripts/dev_dbs.sh start | stop | status
# Postgres: Docker image postgres:17 on :55432 (Chinook + datasets/pg_app_schema.sql)
# MariaDB : Homebrew `mariadb` on :53306        (Chinook + datasets/mysql_app_schema.sql)
# Redis   : Homebrew `redis` on :56379          (datasets/redis_users.redis + sessions)
# MongoDB : Homebrew `mongodb-community` on :57017 (datasets/mflix: users, sessions, comments)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; RUN="$HERE/../.run"; DS="$HERE/datasets"
mkdir -p "$RUN"

start() {
  docker rm -f veil-pg >/dev/null 2>&1 || true
  docker run -d --name veil-pg -e POSTGRES_PASSWORD=veil -p 127.0.0.1:55432:5432 postgres:17 >/dev/null
  until docker exec veil-pg pg_isready -U postgres -q; do sleep 1; done; sleep 1
  docker exec -i veil-pg psql -q -U postgres < "$DS/Chinook_PostgreSql.sql" >/dev/null 2>&1
  docker exec -i veil-pg psql -q -U postgres < "$DS/pg_app_schema.sql" >/dev/null 2>&1

  if [ ! -d "$RUN/mariadb" ]; then
    mariadb-install-db --datadir="$RUN/mariadb" --auth-root-authentication-method=normal --skip-test-db >/dev/null
  fi
  mariadbd --no-defaults --datadir="$RUN/mariadb" --port=53306 --bind-address=127.0.0.1 \
    --socket="$RUN/mariadb.sock" --pid-file="$RUN/mariadb.pid" --log-error="$RUN/mariadb.err" >/dev/null 2>&1 &
  until mariadb --no-defaults -h127.0.0.1 -P53306 -uroot -e "select 1" >/dev/null 2>&1; do sleep 1; done
  mariadb --no-defaults -h127.0.0.1 -P53306 -uroot < "$DS/Chinook_MySql.sql" 2>/dev/null
  mariadb --no-defaults -h127.0.0.1 -P53306 -uroot < "$DS/mysql_app_schema.sql" 2>/dev/null

  redis-server --port 56379 --bind 127.0.0.1 --save "" --appendonly no --dir "$RUN" --daemonize yes \
    --pidfile "$RUN/redis.pid" --logfile "$RUN/redis.log"
  sleep 1; redis-cli -p 56379 FLUSHALL >/dev/null; redis-cli -p 56379 < "$DS/redis_users.redis" >/dev/null
  redis-cli -p 56379 < "$DS/redis_extra.redis" >/dev/null   # JSON sessions + a set of emails
  mkdir -p "$RUN/mongo"
  # (--fork is unsupported on macOS: run in the background and wait for a ping)
  mongod --dbpath "$RUN/mongo" --port 57017 --bind_ip 127.0.0.1 --logpath "$RUN/mongod.log" \
    --pidfilepath "$RUN/mongod.pid" >/dev/null 2>&1 &
  until mongosh --quiet --port 57017 --eval "db.runCommand({ping:1}).ok" >/dev/null 2>&1; do sleep 1; done
  for c in users sessions comments; do
    mongoimport --quiet --port 57017 --db sample_mflix --collection "$c" --drop --file "$DS/mflix/$c.json"
  done
  echo "started: postgres :55432, mariadb :53306, redis :56379, mongodb :57017"
}

stop() {
  docker rm -f veil-pg >/dev/null 2>&1 || true
  [ -f "$RUN/mariadb.pid" ] && kill "$(cat "$RUN/mariadb.pid")" 2>/dev/null || true
  redis-cli -p 56379 shutdown nosave >/dev/null 2>&1 || true
  [ -f "$RUN/mongod.pid" ] && kill "$(cat "$RUN/mongod.pid")" 2>/dev/null || true
  echo "stopped"
}

status() {
  docker ps --filter name=veil-pg --format 'postgres: {{.Status}}' | grep . || echo "postgres: down"
  mariadb --no-defaults -h127.0.0.1 -P53306 -uroot -e "select 1" >/dev/null 2>&1 && echo "mariadb: up" || echo "mariadb: down"
  redis-cli -p 56379 ping 2>/dev/null | grep -q PONG && echo "redis: up" || echo "redis: down"
  mongosh --quiet --port 57017 --eval "db.runCommand({ping:1}).ok" >/dev/null 2>&1 && echo "mongodb: up" || echo "mongodb: down"
}

"${1:-status}"
