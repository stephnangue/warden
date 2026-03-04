#!/usr/bin/env bash
# Collect recent log lines from all nodes.
# Usage: collect_logs.sh [lines]

LINES="${1:-50}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LOGS_DIR="$SCRIPT_DIR/.logs"

for i in 1 2 3; do
  echo "=== Node $i (last $LINES lines) ==="
  tail -n "$LINES" "$LOGS_DIR/node${i}.log" 2>/dev/null || echo "  (no log file)"
  echo ""
done
