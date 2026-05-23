#!/usr/bin/env bash
# Helm chart smoke test. Boots a real warden against a real kind
# cluster, runs `operator init`, asserts the chart-provisioned audit
# device registered. Same script the CI helm-smoke job runs.
#
# Prerequisites on the host:
#   - docker (with buildx), kind, kubectl, helm, openssl, curl, jq
#   - A running kind cluster (this script does NOT create or delete it;
#     see make targets or CI for cluster lifecycle)
#
# Usage (from repo root):
#   bash deploy/helm/warden/ci/smoke.sh [release-name] [namespace] [kind-cluster]
#
# The smoke test uses kubectl port-forward + host curl to talk to the
# warden HTTPS API. This deliberately avoids the warden CLI inside the
# distroless container — distroless has no `env` binary so passing
# WARDEN_ADDR etc. via `kubectl exec` is awkward, and the smoke job's
# scope is validating the chart + server, not exercising the CLI
# (which has its own unit + e2e coverage).
#
# Image build uses `docker buildx build --load` with the multi-stage
# Dockerfile.smoke (golang:1.26 -> distroless). Comfortable inside
# CI's 16 GB ubuntu-latest runners; Docker Desktop with the default
# 8 GB cap may OOM on the AWS SDK compile — bump to 12 GB+ locally.
#
# Defaults: release=warden, namespace=warden, kind-cluster=kind
set -euo pipefail

RELEASE="${1:-warden}"
NS="${2:-warden}"
KIND_CLUSTER="${3:-kind}"
IMAGE_TAG="warden:smoke"

REPO_ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
CI_DIR="$REPO_ROOT/deploy/helm/warden/ci"
CHART_DIR="$REPO_ROOT/deploy/helm/warden"
SMOKE_DOCKERFILE="$REPO_ROOT/deploy/Dockerfile.smoke"

PF_PID=""

cleanup() {
  if [ -n "$PF_PID" ] && kill -0 "$PF_PID" 2>/dev/null; then
    kill "$PF_PID" 2>/dev/null || true
    wait "$PF_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

log() { printf '\033[1;36m[smoke]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[smoke]\033[0m %s\n' "$*" >&2; dump_state; exit 1; }

dump_state() {
  echo "---- failure diagnostics ----" >&2
  kubectl -n "$NS" get all 2>&1 || true
  echo "---- events ----" >&2
  kubectl -n "$NS" get events --sort-by=.lastTimestamp 2>&1 || true
  echo "---- pod describe (warden-0) ----" >&2
  kubectl -n "$NS" describe pod "${RELEASE}-0" 2>&1 || true
  echo "---- pod logs (warden-0, tail=200) ----" >&2
  kubectl -n "$NS" logs "${RELEASE}-0" --tail=200 2>&1 || true
}

# --- 1. Build the smoke image (multi-stage, via buildx). ----------
log "building smoke image $IMAGE_TAG (buildx, multi-stage)"
docker buildx build --load \
  -f "$SMOKE_DOCKERFILE" \
  -t "$IMAGE_TAG" \
  "$REPO_ROOT" >/dev/null

# --- 2. Load it into the kind cluster. -----------------------------
log "loading $IMAGE_TAG into kind cluster '$KIND_CLUSTER'"
kind load docker-image "$IMAGE_TAG" --name "$KIND_CLUSTER"

# --- 3. Namespace + secrets. ---------------------------------------
log "creating namespace $NS"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

log "creating seal-key secret"
bash "$CI_DIR/seal-key.sh" "$NS"

log "creating TLS secret"
bash "$CI_DIR/tls-cert.sh" "$NS" "$RELEASE"

# --- 4. Postgres. --------------------------------------------------
log "applying postgres manifest"
kubectl apply -n "$NS" -f "$CI_DIR/postgres.yaml"
log "waiting for postgres to be ready"
kubectl -n "$NS" wait --for=condition=Available deployment/warden-postgres --timeout=120s

# --- 5. Helm install. ----------------------------------------------
log "helm install $RELEASE"
helm upgrade --install "$RELEASE" "$CHART_DIR" \
  -n "$NS" \
  -f "$CI_DIR/smoke-values.yaml"

# --- 6. Wait for the warden pod to be Running. ---------------------
# Readiness probe needs init+unseal so we can't wait for Ready here.
# PodScheduled + phase=Running is enough to port-forward into.
log "waiting for ${RELEASE}-0 to be schedulable"
kubectl -n "$NS" wait --for=condition=PodScheduled "pod/${RELEASE}-0" --timeout=120s

log "waiting for ${RELEASE}-0 container to be Running"
for i in $(seq 1 60); do
  phase=$(kubectl -n "$NS" get pod "${RELEASE}-0" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  if [ "$phase" = "Running" ]; then
    break
  fi
  if [ "$i" -eq 60 ]; then
    fail "${RELEASE}-0 did not reach Running within 120s (last phase: ${phase:-unknown})"
  fi
  sleep 2
done

# --- 7. Port-forward + wait for the listener to accept. ------------
log "starting kubectl port-forward 8400 -> ${RELEASE}-0:8400"
kubectl -n "$NS" port-forward "pod/${RELEASE}-0" 8400:8400 >/tmp/warden-smoke-pf.log 2>&1 &
PF_PID=$!

# Wait for the port-forward to be ready (sys/health is unauthenticated
# and returns 501 pre-init, which is enough to confirm the listener is up).
log "waiting for the listener to accept connections"
for i in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:8400/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200" \
    2>/dev/null || echo "000")
  if [ "$code" = "200" ]; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    fail "listener did not accept connections within 60s (last code: ${code})"
  fi
  sleep 2
done

# --- 8. Operator init via API. -------------------------------------
log "running sys/init"
INIT_RESP=$(curl -sk -X POST \
  -H "Content-Type: application/json" \
  -d '{"secret_shares":1,"secret_threshold":1}' \
  "https://127.0.0.1:8400/v1/sys/init") \
  || fail "POST /v1/sys/init failed"

ROOT_TOKEN=$(printf '%s' "$INIT_RESP" | jq -r '.root_token // empty')
[ -n "$ROOT_TOKEN" ] || fail "could not extract root_token from init response: $INIT_RESP"

# --- 9. Wait for cluster to reach active. --------------------------
# Static seal auto-unseals after init. Poll sys/health until the
# unauthenticated 200 fires (active leader).
log "waiting for cluster to reach active"
for i in $(seq 1 30); do
  code=$(curl -sk -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:8400/v1/sys/health" \
    2>/dev/null || echo "000")
  if [ "$code" = "200" ]; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    fail "cluster did not reach active within 60s (last sys/health: ${code})"
  fi
  sleep 2
done

# --- 10. Assertions. -----------------------------------------------
log "asserting declarative audit device is registered"
AUDIT_JSON=$(curl -sk -H "X-Warden-Token: $ROOT_TOKEN" \
  "https://127.0.0.1:8400/v1/sys/audit?warden-list=true") \
  || fail "GET /v1/sys/audit failed"

# The list endpoint returns a map keyed by audit path; each value has
# a `declarative` bool added by the audit-hcl PR. Use jq for a real
# parse rather than a string grep.
DECLARATIVE_COUNT=$(printf '%s' "$AUDIT_JSON" | jq '[..|.declarative? // empty | select(.==true)] | length')
[ "${DECLARATIVE_COUNT:-0}" -ge 1 ] \
  || fail "expected >=1 declarative audit device; got ${DECLARATIVE_COUNT:-0}. Full response: $AUDIT_JSON"

log "smoke test PASSED — $DECLARATIVE_COUNT declarative audit device(s), cluster active"
