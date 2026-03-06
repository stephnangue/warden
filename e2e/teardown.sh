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

echo "=== Warden E2E Cluster Teardown ==="
echo ""

# Stop all Warden nodes
echo "Stopping Warden nodes..."
for i in 1 2 3; do
  PID_FILE="$SCRIPT_DIR/.pids/node${i}.pid"
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      kill "$PID" 2>/dev/null && echo "  Stopped node $i (PID $PID)" || echo "  Node $i not running"
    else
      echo "  Node $i already stopped (PID $PID)"
    fi
    rm -f "$PID_FILE"
  else
    echo "  Node $i: no PID file"
  fi
done

# Stop all Docker services (PostgreSQL, Vault, Hydra)
echo ""
echo "Stopping Docker services (PostgreSQL, Vault, Hydra)..."
$DOCKER_COMPOSE -f "$SCRIPT_DIR/docker-compose.yml" down -v 2>/dev/null || true

# Clean up generated files
echo ""
echo "Cleaning up generated files..."
rm -f "$SCRIPT_DIR/configs/seal.key"
rm -f "$SCRIPT_DIR/configs/warden-audit.log"
rm -f "$SCRIPT_DIR/.root_token"
rm -f "$SCRIPT_DIR/.logs"/*.log
rm -rf "$SCRIPT_DIR/loadbalancer/certs"

echo ""
echo "Teardown complete."
