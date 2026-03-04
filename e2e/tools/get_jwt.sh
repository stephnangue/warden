#!/usr/bin/env bash
# Get a JWT from Ory Hydra via client_credentials grant.
# Usage: get_jwt.sh [client_id] [client_secret] [scope]
#
# Defaults to the "e2e-agent" client created during setup.
#
# Examples:
#   get_jwt.sh                                    # default e2e-agent client
#   get_jwt.sh e2e-pipeline pipeline-secret       # pipeline client
#   get_jwt.sh e2e-admin admin-secret "api:admin" # admin with custom scope

CLIENT_ID="${1:-e2e-agent}"
CLIENT_SECRET="${2:-agent-secret}"
SCOPE="${3:-api:read api:write}"

RESPONSE=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=${SCOPE}" 2>/dev/null)

# Extract access_token from JSON response
TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

if [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to get JWT from Hydra" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

echo "$TOKEN"
