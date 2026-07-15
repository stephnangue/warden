#!/bin/sh
# Idempotent OpenBao test-data seed for the policy-hygiene tutorial.
# Writes five policies that each exhibit one hygiene smell (plus one clean
# baseline) and attaches `clean` to a named identity entity so it has a live
# binding. This is what the audit agent inspects in section 8.
set -eu

bao auth list -format=json 2>/dev/null | grep -q '"userpass/"' \
  || bao auth enable userpass

# Clean baseline — single read-only path on a real mount, no smells.
bao policy write clean - <<'EOF'
path "secret/data/team-a/*" {
  capabilities = ["read"]
}
EOF

# Smell: sudo + wildcard at top level.
bao policy write root-ish - <<'EOF'
path "*" {
  capabilities = ["sudo", "read", "list"]
}
EOF

# Smell: paths reference mounts that don't exist (kv-legacy, aws-prod).
bao policy write dead-mount - <<'EOF'
path "kv-legacy/*" {
  capabilities = ["read"]
}
path "aws-prod/creds/admin" {
  capabilities = ["read"]
}
EOF

# Smell: same path declared twice with different capabilities.
bao policy write duplicates - <<'EOF'
path "secret/data/app/*" {
  capabilities = ["read"]
}
path "secret/data/app/*" {
  capabilities = ["read", "delete"]
}
EOF

# Smell: not bound to any entity (the agent should flag it).
bao policy write orphan - <<'EOF'
path "secret/data/legacy-batch-job/*" {
  capabilities = ["read"]
}
EOF

# Anchor: attach `clean` to a named entity so the agent can verify
# at-least-one-binding logic. `bao write identity/entity name=...` upserts
# by name, so re-runs replace the entry instead of duplicating it.
bao write identity/entity name=anchor-user policies=clean >/dev/null

echo "bao-seed: wrote clean / root-ish / dead-mount / duplicates / orphan; bound clean to anchor-user"
