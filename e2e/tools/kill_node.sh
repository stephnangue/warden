#!/usr/bin/env bash
# Kill a specific Warden node by number.
# Usage: kill_node.sh <node_number> [TERM|KILL]
# node_number: 1, 2, or 3
# signal: TERM (default) or KILL

NODE="${1:?Usage: kill_node.sh <1|2|3> [TERM|KILL]}"
SIGNAL="${2:-TERM}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$SCRIPT_DIR/.pids/node${NODE}.pid"

if [ ! -f "$PID_FILE" ]; then
  echo "PID file not found for node $NODE"
  exit 1
fi

PID=$(cat "$PID_FILE")
if kill -0 "$PID" 2>/dev/null; then
  kill -"${SIGNAL}" "$PID" 2>/dev/null
  echo "Killed node $NODE (PID $PID) with SIG${SIGNAL}"
else
  echo "Node $NODE (PID $PID) is not running"
fi
