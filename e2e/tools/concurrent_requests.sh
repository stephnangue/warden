#!/usr/bin/env bash
# Fire N concurrent requests and report results.
# Usage: concurrent_requests.sh <count> <method> <path> [port]
#
# Example:
#   concurrent_requests.sh 20 GET sys/health 8500

COUNT="${1:?Usage: concurrent_requests.sh <count> <method> <path> [port]}"
METHOD="${2:?Usage: concurrent_requests.sh <count> <method> <path> [port]}"
PATH_="${3:?Usage: concurrent_requests.sh <count> <method> <path> [port]}"
PORT="${4:-8500}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOKEN=$(cat "$SCRIPT_DIR/.root_token" 2>/dev/null || echo "")

TMPDIR=$(mktemp -d)
echo "Firing $COUNT concurrent $METHOD requests to /v1/$PATH_ on port $PORT..."

for i in $(seq 1 "$COUNT"); do
  (
    ARGS=(-sk -X "$METHOD" "https://127.0.0.1:${PORT}/v1/${PATH_}" -w "%{http_code}" -o "$TMPDIR/body_${i}.json")
    if [ -n "$TOKEN" ]; then
      ARGS+=(-H "X-Warden-Token: $TOKEN")
    fi
    HTTP_CODE=$(curl "${ARGS[@]}" 2>/dev/null)
    echo "$HTTP_CODE" > "$TMPDIR/status_${i}"
  ) &
done
wait

echo ""
echo "Results:"
SUCCESS=0
FAIL=0
for i in $(seq 1 "$COUNT"); do
  STATUS=$(cat "$TMPDIR/status_${i}" 2>/dev/null || echo "000")
  if [ "$STATUS" = "200" ] || [ "$STATUS" = "429" ]; then
    SUCCESS=$((SUCCESS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "  Request $i: HTTP $STATUS"
  fi
done
echo "  Success: $SUCCESS/$COUNT, Failed: $FAIL/$COUNT"

rm -rf "$TMPDIR"
