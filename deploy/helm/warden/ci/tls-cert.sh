#!/usr/bin/env bash
# Generate a self-signed ECDSA TLS cert + matching CA bundle for the
# warden API listener and kubectl-create the Secret the chart's
# tls.existingSecret path expects. Mirrors e2e/setup.sh:34-52.
#
# SANs cover the in-cluster service DNS names the StatefulSet uses,
# plus 127.0.0.1 for the `kubectl exec` health-check poll. Self-signed,
# 1-day duration — only ever used in CI.
#
# Usage: bash tls-cert.sh <namespace> <release-name>
set -euo pipefail

NS="${1:?namespace required}"
RELEASE="${2:?release name required (e.g. warden)}"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

SAN="subjectAltName=DNS:${RELEASE},DNS:${RELEASE}.${NS}.svc,DNS:${RELEASE}.${NS}.svc.cluster.local,DNS:${RELEASE}-headless,DNS:${RELEASE}-headless.${NS}.svc,DNS:${RELEASE}-headless.${NS}.svc.cluster.local,DNS:*.${RELEASE}-headless.${NS}.svc.cluster.local,DNS:localhost,IP:127.0.0.1"

# CA — self-signed, only used to satisfy the chart's tls_client_ca_file
# mount; mTLS is off in smoke (tls.requireClientCert=false default).
openssl ecparam -genkey -name prime256v1 -noout -out "$TMPDIR/ca.key" 2>/dev/null
openssl req -x509 -new -key "$TMPDIR/ca.key" -out "$TMPDIR/ca.crt" \
  -days 1 -subj "/CN=warden-smoke-ca/O=Warden Smoke" 2>/dev/null

# Server cert signed by the CA.
openssl ecparam -genkey -name prime256v1 -noout -out "$TMPDIR/tls.key" 2>/dev/null
openssl req -new -key "$TMPDIR/tls.key" -out "$TMPDIR/tls.csr" \
  -subj "/CN=${RELEASE}/O=Warden Smoke" 2>/dev/null
openssl x509 -req -in "$TMPDIR/tls.csr" \
  -CA "$TMPDIR/ca.crt" -CAkey "$TMPDIR/ca.key" -CAcreateserial \
  -out "$TMPDIR/tls.crt" -days 1 \
  -extfile <(printf '%s' "$SAN") 2>/dev/null

kubectl -n "$NS" create secret generic warden-tls \
  --from-file=tls.crt="$TMPDIR/tls.crt" \
  --from-file=tls.key="$TMPDIR/tls.key" \
  --from-file=ca.crt="$TMPDIR/ca.crt" \
  --dry-run=client -o yaml | kubectl apply -f -
