#!/bin/sh

set -e

echo "Creating Client 1: agent"
wget --post-data='{
  "client_id": "agent",
  "client_name": "Agent",
  "client_secret": "test@agent",
  "grant_types": ["client_credentials"],
  "response_types": [],
  "scope": "api:read api:write",
  "token_endpoint_auth_method": "client_secret_post"
}' \
  --header="Content-Type: application/json" \
  -O- \
  http://hydra:4445/admin/clients

echo ""
echo "Creating Client 2: gilab-job"
wget --post-data='{
  "client_id": "gilab-job",
  "client_name": "gilab-job",
  "client_secret": "test@gilab-job",
  "grant_types": ["client_credentials"],
  "response_types": [],
  "scope": "api:read api:write",
  "token_endpoint_auth_method": "client_secret_post"
}' \
  --header="Content-Type: application/json" \
  -O- \
  http://hydra:4445/admin/clients

echo ""
echo "Creating Client 3: kube-pod"
wget --post-data='{
  "client_id": "kube-pod",
  "client_name": "kube-pod",
  "client_secret": "test@kube-pod",
  "grant_types": ["client_credentials"],
  "response_types": [],
  "scope": "api:read api:write",
  "token_endpoint_auth_method": "client_secret_post"
}' \
  --header="Content-Type: application/json" \
  -O- \
  http://hydra:4445/admin/clients

echo ""
echo "Creating Client 4: admin"
wget --post-data='{
  "client_id": "admin",
  "client_name": "admin",
  "client_secret": "pass@admin",
  "grant_types": ["client_credentials"],
  "response_types": [],
  "scope": "api:admin api:read",
  "token_endpoint_auth_method": "client_secret_post"
}' \
  --header="Content-Type: application/json" \
  -O- \
  http://hydra:4445/admin/clients

echo ""
echo "==================== CLIENTS CREATED ===================="
echo ""
echo "Client 1:"
echo "  Client ID: service-client-1"
echo "  Client Secret: service-secret-1-change-this"
echo "  Scopes: api:read, api:write"
echo ""
echo "Client 2:"
echo "  Client ID: service-client-2"
echo "  Client Secret: service-secret-2-change-this"
echo "  Scopes: api:admin, api:read"
echo ""
echo "========================================================="
echo ""
echo "Test with:"
echo "curl -X POST http://localhost:4444/oauth2/token \\"
echo "  -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "  -d 'grant_type=client_credentials&client_id=service-client-1&client_secret=service-secret-1-change-this&scope=api:read api:write'"
echo ""