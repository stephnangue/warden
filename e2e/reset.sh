#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-detect docker compose CLI (v2 plugin vs v1 standalone)
if docker compose version &>/dev/null; then
  DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  DOCKER_COMPOSE="docker-compose"
else
  echo "ERROR: Neither 'docker compose' nor 'docker-compose' found"
  exit 1
fi

echo "=== Warden E2E Full Reset ==="
echo ""

# Stop all Warden nodes first
echo "Stopping Warden nodes..."
for i in 1 2 3; do
  PID_FILE="$SCRIPT_DIR/.pids/node${i}.pid"
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    kill "$PID" 2>/dev/null && echo "  Stopped node $i (PID $PID)" || true
    rm -f "$PID_FILE"
  fi
done
sleep 2

# Tear down all Docker services (including Vault and Hydra) for clean state
echo ""
echo "Stopping all Docker services..."
$DOCKER_COMPOSE -f "$SCRIPT_DIR/docker-compose.yml" down -v 2>/dev/null || true

# Restart infrastructure fresh
echo ""
echo "Starting infrastructure (PostgreSQL, Vault, Hydra)..."
$DOCKER_COMPOSE -f "$SCRIPT_DIR/docker-compose.yml" up -d
until docker exec e2e-postgres-warden pg_isready -U warden -q 2>/dev/null; do
  sleep 1
done

# Drop E2E tables
echo ""
echo "Dropping E2E tables..."
docker exec e2e-postgres-warden psql -U warden -d warden -c \
  "DROP TABLE IF EXISTS e2e_ha_locks; DROP TABLE IF EXISTS e2e_kv_store;"

# Clean up local state
echo ""
echo "Cleaning up local state..."
rm -f "$SCRIPT_DIR/.root_token"
rm -f "$SCRIPT_DIR/.logs"/*.log
rm -f "$SCRIPT_DIR/configs/seal.key"
rm -f "$SCRIPT_DIR/configs/warden-audit.log"

echo ""
echo "Full reset complete. Run 'bash e2e/setup.sh' to start fresh."
