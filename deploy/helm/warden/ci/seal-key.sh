#!/usr/bin/env bash
# Generate a 32-byte AES-256-GCM-96 seal key and kubectl-create the
# Secret the chart's static-seal path expects (mounted at /seal/key).
# Mirrors the pattern at e2e/setup.sh:148-152.
#
# Usage: bash seal-key.sh <namespace>
set -euo pipefail

NS="${1:?namespace required}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

openssl rand 32 > "$TMPDIR/seal.key"

kubectl -n "$NS" create secret generic warden-seal \
  --from-file=current_key="$TMPDIR/seal.key" \
  --dry-run=client -o yaml | kubectl apply -f -
