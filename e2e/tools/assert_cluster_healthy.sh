#!/usr/bin/env bash
# Verify the cluster is in a healthy state:
# - Exactly 1 leader
# - All 3 nodes responding
# - No sealed nodes
#
# Exit code 0 = healthy, 1 = unhealthy

ERRORS=0
LEADER_COUNT=0
STANDBY_COUNT=0
UNREACHABLE=0

for port in 8500 8510 8520; do
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1:${port}/v1/sys/health" 2>/dev/null || echo "000")
  case "$HTTP_CODE" in
    200)
      LEADER_COUNT=$((LEADER_COUNT + 1))
      echo "Port $port: ACTIVE (200)"
      ;;
    429)
      STANDBY_COUNT=$((STANDBY_COUNT + 1))
      echo "Port $port: STANDBY (429)"
      ;;
    503)
      echo "Port $port: SEALED (503)"
      ERRORS=$((ERRORS + 1))
      ;;
    000)
      echo "Port $port: UNREACHABLE"
      UNREACHABLE=$((UNREACHABLE + 1))
      ERRORS=$((ERRORS + 1))
      ;;
    *)
      echo "Port $port: UNEXPECTED ($HTTP_CODE)"
      ERRORS=$((ERRORS + 1))
      ;;
  esac
done

echo ""
if [ "$LEADER_COUNT" -ne 1 ]; then
  echo "ASSERTION FAILED: Expected 1 leader, found $LEADER_COUNT"
  ERRORS=$((ERRORS + 1))
fi

if [ "$ERRORS" -gt 0 ]; then
  echo "CLUSTER UNHEALTHY ($ERRORS errors, $LEADER_COUNT leaders, $STANDBY_COUNT standbys, $UNREACHABLE unreachable)"
  exit 1
fi

echo "CLUSTER HEALTHY (1 leader, 2 standbys)"
exit 0
