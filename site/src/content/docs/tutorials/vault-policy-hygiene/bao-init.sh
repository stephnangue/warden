#!/bin/sh
# Idempotent OpenBao bootstrap for the Warden policy-hygiene tutorial.
#
# Enables AppRole, creates the policy-reader ACL + token role that Warden's
# minted tokens use, and provisions the warden-policy-scanner AppRole that
# Warden itself authenticates with. Writes ROLE_ID/SECRET_ID to /out/creds.env
# for the host to source.
set -eu

bao auth list -format=json 2>/dev/null | grep -q '"approle/"' \
  || bao auth enable approle

bao policy write policy-reader-acl - <<'EOF'
path "sys/policies/acl/*"   { capabilities = ["read", "list"] }
path "sys/mounts"           { capabilities = ["read"] }
path "sys/auth"             { capabilities = ["read"] }
path "identity/entity/id"   { capabilities = ["list"] }
path "identity/entity/id/*" { capabilities = ["read"] }
EOF

bao write auth/token/roles/policy-reader \
  allowed_policies=policy-reader-acl \
  orphan=true period=10m

bao policy write warden-vault-source - <<'EOF'
path "auth/token/create/policy-reader"          { capabilities = ["update"] }
path "auth/approle/role/warden-policy-scanner"  { capabilities = ["read"] }
EOF

bao write auth/approle/role/warden-policy-scanner \
  token_policies=warden-vault-source \
  token_ttl=1h token_max_ttl=24h

ROLE_ID=$(bao read -field=role_id auth/approle/role/warden-policy-scanner/role-id)
SECRET_ID=$(bao write -force -field=secret_id auth/approle/role/warden-policy-scanner/secret-id)

mkdir -p /out
cat > /out/creds.env <<EOF
ROLE_ID=$ROLE_ID
SECRET_ID=$SECRET_ID
EOF

echo "bao-init: wrote /out/creds.env"
