#!/bin/sh

set -e

echo "Creating Client 1: service-client-1"
curl -X POST http://hydra:4445/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "service-client-1",
    "client_name": "Service Client 1",
    "client_secret": "service-secret-1-change-this",
    "grant_types": ["client_credentials"],
    "response_types": [],
    "scope": "api:read api:write",
    "token_endpoint_auth_method": "client_secret_post"
  }'

echo ""
echo "Creating Client 2: service-client-2"
curl -X POST http://hydra:4445/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "service-client-2",
    "client_name": "Service Client 2",
    "client_secret": "service-secret-2-change-this",
    "grant_types": ["client_credentials"],
    "response_types": [],
    "scope": "api:admin api:read",
    "token_endpoint_auth_method": "client_secret_post"
  }'

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