#!/usr/bin/env bash
# Restart a previously killed Warden node.
# Usage: restart_node.sh <node_number>

NODE="${1:?Usage: restart_node.sh <1|2|3>}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$SCRIPT_DIR/.bin"
LOGS_DIR="$SCRIPT_DIR/.logs"
PIDS_DIR="$SCRIPT_DIR/.pids"

if [ ! -f "$BIN_DIR/warden" ]; then
  echo "Warden binary not found at $BIN_DIR/warden"
  exit 1
fi

# Kill existing process if still running
PID_FILE="$PIDS_DIR/node${NODE}.pid"
if [ -f "$PID_FILE" ]; then
  OLD_PID=$(cat "$PID_FILE")
  kill "$OLD_PID" 2>/dev/null || true
  sleep 1
fi

echo "Restarting node $NODE..."
cd "$SCRIPT_DIR/configs"
"$BIN_DIR/warden" server --config="$SCRIPT_DIR/configs/node${NODE}.hcl" \
  >> "$LOGS_DIR/node${NODE}.log" 2>&1 &
echo $! > "$PIDS_DIR/node${NODE}.pid"
echo "Node $NODE restarted (PID: $(cat "$PIDS_DIR/node${NODE}.pid"))"
