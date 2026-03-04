#!/usr/bin/env bash
# Check health of all nodes or a specific node.
# Usage: health_check.sh [port]
# If no port given, checks all three nodes.

PORTS="${1:-8500 8510 8520}"
for port in $PORTS; do
  echo "=== Node :${port} ==="
  BODY=$(curl -s "http://127.0.0.1:${port}/v1/sys/health" 2>/dev/null)
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/v1/sys/health" 2>/dev/null || echo "000")
  echo "  HTTP: $HTTP_CODE"
  if [ -n "$BODY" ]; then
    echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "  $BODY"
  else
    echo "  (no response)"
  fi
done
