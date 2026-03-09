#!/usr/bin/env bash
# Identify which node is the current leader.
# Usage: get_leader.sh

for port in 8500 8510 8520; do
  RESULT=$(curl -sk "https://127.0.0.1:${port}/v1/sys/leader" 2>/dev/null)
  IS_SELF=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('is_self', False))" 2>/dev/null)
  if [ "$IS_SELF" = "True" ]; then
    echo "Leader: node on port $port"
    echo "$RESULT" | python3 -m json.tool 2>/dev/null
    exit 0
  fi
done
echo "No leader found"
exit 1
