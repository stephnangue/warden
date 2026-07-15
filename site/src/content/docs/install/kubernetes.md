---
title: "Deploying Warden on Kubernetes"
---

This guide walks through installing Warden on a Kubernetes cluster using the
first-party Helm chart at [`deploy/helm/warden/`](https://github.com/stephnangue/warden/tree/main/deploy/helm/warden/).

The chart deploys a 3-replica HA cluster by default: one active leader and
two hot standbys, backed by an external PostgreSQL database, with TLS on
the API listener and auto-unseal via HashiCorp Vault Transit. A dev profile
(`values-dev.yaml`) shrinks the install to a single replica using a static
seal key for quick local testing on kind or minikube.

- [Architecture overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Installing the chart](#installing-the-chart)
- [Dev quickstart on kind](#dev-quickstart-on-kind)
- [Production install](#production-install)
- [PostgreSQL options](#postgresql-options)
- [Streamlined TLS with cert-manager](#streamlined-tls-with-cert-manager)
- [First-time initialization](#first-time-initialization)
- [Upgrades](#upgrades)
- [Operations](#operations)
- [Cleanup](#cleanup)
- [Troubleshooting](#troubleshooting)

---

## Architecture overview

The chart renders these objects per release:

| Object | Purpose |
|---|---|
| `StatefulSet/<release>` | Warden pods with stable per-pod DNS names. `podManagementPolicy: Parallel` — leader election is lock-based and doesn't require ordered startup. |
| `Service/<release>` (ClusterIP) | Client-facing API on port 8400. Readiness probe gates sealed/uninit pods out automatically. |
| `Service/<release>-headless` (clusterIP None, `publishNotReadyAddresses: true`) | Per-pod DNS for inter-node mTLS forwarding on 8401, and for operator access while pods are NotReady. |
| `ConfigMap/<release>-config` | HCL config files mounted at `/config`. References env vars via `{{ env "VAR" }}`. |
| `Secret/<release>-credentials` | _Only when literal credentials were passed via values_ — the chart-managed Secret used for the dev quickstart path. |
| `ServiceAccount/<release>` | `automountServiceAccountToken: false`. Warden does not call the Kubernetes API. |
| `PodDisruptionBudget/<release>` | `maxUnavailable: 1`. Bounds voluntary disruption during node drains and rolling upgrades. |

Three pods become one active leader (via Postgres advisory locks) and two
standbys. Standbys forward writes to the leader over mTLS on port 8401.
On leader failure, a standby acquires the lock within ~10s. See the
[Architecture doc](/architecture/) for the high-availability model.

---

## Prerequisites

- **Kubernetes 1.27+** — the chart depends on GA semantics of
  `publishNotReadyAddresses` on headless Services.
- **PostgreSQL** — bring your own. The chart never bundles a database.
  See [PostgreSQL options](#postgresql-options) for examples.
- **TLS certificate** — Warden requires TLS on the API listener. Either
  provide a Kubernetes Secret of type `kubernetes.io/tls` (with optional
  `ca.crt` for client-cert validation) or set `tls.certManager.enabled=true`
  to have cert-manager issue and rotate it. See
  [Streamlined TLS with cert-manager](#streamlined-tls-with-cert-manager).
- **Seal infrastructure** — for production, a Vault server with a Transit
  key configured for auto-unseal. For dev, a single shared static seal
  key carried in a Secret.
- **`helm` 3.16+** and **`kubectl`** locally.
- **cert-manager (optional)** — required only when `tls.certManager.enabled=true`.
  Any v1.x install works; the chart references whatever `Issuer` or
  `ClusterIssuer` you point it at.

---

## Installing the chart

The chart is published to the GitHub Container Registry on every release
tag, as an OCI artifact alongside the Warden Docker image. Pick the
method that matches your environment.

### From the OCI registry (recommended)

Helm 3.8+ pulls OCI charts natively — no `helm repo add` needed:

```bash
helm install warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  -n warden --create-namespace \
  -f your-values.yaml
```

`--version` refers to the *chart* version (currently `0.1.0`), which is
independent of the Warden binary version. The chart pins the matching
Warden image automatically via the release pipeline.

To pin to a specific Warden binary version against the same chart:

```bash
helm install warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  --set image.tag=v0.17.0 \
  -n warden --create-namespace \
  -f your-values.yaml
```

### From a release tarball (air-gapped)

For clusters that cannot reach OCI registries — for example, those
restricted to an internal mirror — every release also attaches the chart
tarball to the GitHub Release page:

```bash
curl -L -o warden-chart.tgz \
  https://github.com/stephnangue/warden/releases/download/v0.17.0/warden-0.3.3.tgz

helm install warden ./warden-chart.tgz \
  -n warden --create-namespace \
  -f your-values.yaml
```

### From the source repo (development)

For chart development or to install an unreleased version:

```bash
git clone https://github.com/stephnangue/warden
helm install warden ./warden/deploy/helm/warden \
  -n warden --create-namespace \
  -f your-values.yaml
```

The commands in the rest of this guide use the OCI form. Substitute the
local-path form (`./deploy/helm/warden`) if you are working from a clone.

---

## Dev quickstart on kind

A complete end-to-end install on a local kind cluster. Total time ~5 min.

### 1. Create a cluster and namespace

```bash
kind create cluster --name warden
kubectl create namespace warden
```

### 2. Deploy PostgreSQL

A bare-minimum single-pod Postgres for dev only:

```bash
cat <<'EOF' | kubectl apply -n warden -f -
apiVersion: v1
kind: Secret
metadata:
  name: warden-postgres-creds
stringData:
  POSTGRES_USER: warden
  POSTGRES_PASSWORD: warden
  POSTGRES_DB: warden
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: warden-postgres
spec:
  serviceName: warden-postgres
  replicas: 1
  selector:
    matchLabels: { app: warden-postgres }
  template:
    metadata:
      labels: { app: warden-postgres }
    spec:
      containers:
        - name: postgres
          image: postgres:16-alpine
          envFrom: [{ secretRef: { name: warden-postgres-creds } }]
          ports: [{ containerPort: 5432 }]
---
apiVersion: v1
kind: Service
metadata:
  name: warden-postgres
spec:
  selector: { app: warden-postgres }
  ports: [{ port: 5432 }]
EOF

kubectl -n warden wait --for=condition=Ready pod/warden-postgres-0 --timeout=2m
```

### 3. Create the TLS Secret

Generate a self-signed cert for testing:

```bash
mkdir -p /tmp/warden-tls
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=warden.warden.svc" \
  -addext "subjectAltName=DNS:warden,DNS:warden.warden.svc,DNS:warden.warden.svc.cluster.local,DNS:*.warden-headless.warden.svc.cluster.local" \
  -keyout /tmp/warden-tls/tls.key \
  -out /tmp/warden-tls/tls.crt

# CA bundle (self-signed cert is its own CA)
cp /tmp/warden-tls/tls.crt /tmp/warden-tls/ca.crt

kubectl -n warden create secret generic warden-tls \
  --from-file=/tmp/warden-tls/tls.crt \
  --from-file=/tmp/warden-tls/tls.key \
  --from-file=/tmp/warden-tls/ca.crt
```

### 4. Create the static seal Secret

```bash
# 32 raw bytes for AES-256-GCM (NOT base64-encoded — Warden reads the
# file verbatim, mirroring the format used by e2e/setup.sh).
openssl rand 32 > /tmp/warden-seal.key
kubectl -n warden create secret generic warden-seal \
  --from-file=current_key=/tmp/warden-seal.key
```

### 5. Install the chart

The dev values file lives inside the chart, so for the OCI install path
download it first with `helm show values`:

```bash
helm show values oci://ghcr.io/stephnangue/charts/warden --version 0.3.3 \
  > /tmp/warden-values.yaml
# Edit /tmp/warden-values.yaml — or skip this step and use --set flags only.

helm install warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  -n warden \
  --set replicaCount=1 \
  --set seal.type=static \
  --set podDisruptionBudget.enabled=false \
  --set tls.existingSecret=warden-tls \
  --set storage.connectionUrl='postgres://warden:warden@warden-postgres:5432/warden?sslmode=disable' \
  --set seal.static.existingSecret=warden-seal \
  --set seal.static.keyId=dev-$(date +%Y%m%d)
```

If you have the source repo cloned, the equivalent using the bundled
`values-dev.yaml` is one flag:

```bash
helm install warden ./deploy/helm/warden \
  -n warden \
  -f ./deploy/helm/warden/values-dev.yaml \
  --set tls.existingSecret=warden-tls \
  --set storage.connectionUrl='postgres://warden:warden@warden-postgres:5432/warden?sslmode=disable' \
  --set seal.static.existingSecret=warden-seal \
  --set seal.static.keyId=dev-$(date +%Y%m%d)
```

Pods will start uninitialized — readiness fails with 501 and they are not
yet in the `warden` Service endpoints. This is expected. See
[First-time initialization](#first-time-initialization) for the next step.

---

## Production install

### 1. Decide on auto-unseal

Use HashiCorp Vault Transit auto-unseal so pods unseal themselves on every
restart without operator intervention. Static seals require manual unseal
on each restart and are not appropriate for production.

Set up a Transit key on your Vault server:

```bash
vault secrets enable transit
vault write -f transit/keys/warden-unseal

# Policy that only allows encrypt/decrypt on the unseal key:
vault policy write warden-unseal - <<'EOF'
path "transit/encrypt/warden-unseal" { capabilities = ["update"] }
path "transit/decrypt/warden-unseal" { capabilities = ["update"] }
EOF

# Long-lived periodic token (auto-renewed by Warden):
vault token create -policy=warden-unseal -period=720h -orphan \
  -display-name=warden-unseal -format=json | jq -r .auth.client_token
# Save the token — you will store it in the warden-seal-token Secret below.
```

### 2. Provision secrets

Operator-managed Secrets are referenced from values rather than baked into
the chart-rendered ConfigMap. For each, create a Secret in the warden
namespace:

```bash
kubectl -n warden create secret generic warden-db \
  --from-literal=connection_url='postgres://warden:STRONG_PASSWORD@db.internal:5432/warden?sslmode=require'

kubectl -n warden create secret generic warden-seal-token \
  --from-literal=token='hvs.SOME_VAULT_TOKEN'

kubectl -n warden create secret tls warden-tls \
  --cert=./warden-tls.crt --key=./warden-tls.key
# Append the CA bundle if you need client-cert validation. Note: `base64 -w0`
# is GNU; on macOS use `base64 -i ./ca.crt` and strip the trailing newline.
kubectl -n warden patch secret warden-tls --type=merge \
  -p '{"data":{"ca.crt":"'"$(base64 < ./ca.crt | tr -d '\n')"'"}}'
```

If you use [External Secrets Operator](https://external-secrets.io) or
[secrets-store-csi-driver](https://secrets-store-csi-driver.sigs.k8s.io/),
reference your synced Secret names via `--set` instead.

### 3. Install the chart

```bash
helm install warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  -n warden --create-namespace \
  --set tls.existingSecret=warden-tls \
  --set storage.existingSecret=warden-db \
  --set seal.transit.address=https://vault.internal:8200 \
  --set seal.transit.keyName=warden-unseal \
  --set seal.transit.existingSecret=warden-seal-token \
  --set replicaCount=3
```

Pods will start uninitialized — proceed to
[First-time initialization](#first-time-initialization).

### 4. Notable defaults that you may want to override

- `image.tag` — defaults to the chart's `appVersion`. Override to pin a
  specific Warden release independently of the chart version.
- `resources` — 100m CPU / 256Mi memory request, 512Mi memory limit. Bump
  for high-throughput deployments.
- `topologySpreadConstraints` — defaults to one entry spreading pods
  across `topology.kubernetes.io/zone` with `whenUnsatisfiable:
  ScheduleAnyway`. Tighten to `DoNotSchedule` if your cluster has
  guaranteed multi-zone capacity.
- `tls.requireClientCert` — set to `true` for mTLS on the API listener.
  Clients must present a certificate signed by the CA in `ca.crt`.

---

## PostgreSQL options

The chart never bundles PostgreSQL. Recommended approaches:

### Bitnami postgresql Helm chart

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install warden-db bitnami/postgresql -n warden \
  --set auth.username=warden \
  --set auth.database=warden \
  --set primary.persistence.size=10Gi

# Wait for it, then capture the credentials Helm generated:
DB_PW=$(kubectl -n warden get secret warden-db-postgresql \
  -o jsonpath='{.data.password}' | base64 -d)

kubectl -n warden create secret generic warden-db \
  --from-literal=connection_url="postgres://warden:${DB_PW}@warden-db-postgresql:5432/warden?sslmode=require"
```

### CloudNativePG

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: warden-db
  namespace: warden
spec:
  instances: 3
  storage:
    size: 20Gi
  bootstrap:
    initdb:
      database: warden
      owner: warden
```

CloudNativePG creates a Secret called `warden-db-app` containing both
`username` / `password` and a `uri` field with the full connection
string. Set `storage.existingSecret=warden-db-app` and
`storage.connectionUrlKey=uri`.

### Managed Postgres (RDS, Cloud SQL, Aiven, etc.)

Create a Secret out-of-band with the full connection URL and reference it
via `--set storage.existingSecret=<name>`. Use `sslmode=require` (or
stricter) on production databases.

---

## Streamlined TLS with cert-manager

If [cert-manager](https://cert-manager.io) is installed in the cluster,
setting `tls.certManager.enabled=true` replaces the
"openssl + `kubectl create secret`" dance with a single chart-rendered
`Certificate` resource. cert-manager issues the cert against an `Issuer`
or `ClusterIssuer` you already trust, writes the `kubernetes.io/tls`
Secret the StatefulSet mounts, and renews automatically before expiry.

`tls.existingSecret` and `tls.certManager.enabled` are mutually
exclusive — preflight rejects both.

### Defaults you get out of the box

| Field | Default |
|---|---|
| `secretName` | `{fullname}-tls` (override with `tls.certManager.secretName`) |
| `dnsNames` | `{fullname}`, `{fullname}.{ns}.svc`, `{fullname}.{ns}.svc.cluster.local`, `*.{fullname}-headless.{ns}.svc.cluster.local` |
| `duration` / `renewBefore` | `2160h` (90d) / `360h` (15d) |
| `privateKey` | ECDSA P-256, `rotationPolicy: Always` |
| `usages` | `[server auth]`, plus `client auth` when `tls.requireClientCert=true` |

Required input: `tls.certManager.issuerRef.name`. The chart does **not**
create the Issuer — that is environment policy and typically lives in a
different namespace.

### Production: Vault PKI or internal CA

```bash
helm install warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  -n warden --create-namespace \
  --set tls.certManager.enabled=true \
  --set tls.certManager.issuerRef.name=warden-pki \
  --set tls.certManager.issuerRef.kind=ClusterIssuer \
  --set storage.existingSecret=warden-db \
  --set seal.transit.address=https://vault.internal:8200 \
  --set seal.transit.keyName=warden-unseal \
  --set seal.transit.existingSecret=warden-seal-token
```

### Dev: self-signed `ClusterIssuer` on kind

The dev quickstart [Step 3 (TLS Secret)](#3-create-the-tls-secret) can be
replaced with cert-manager. Install cert-manager once per cluster, apply a
self-signed `ClusterIssuer`, and let the chart handle the rest:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.0/cert-manager.yaml
kubectl -n cert-manager wait --for=condition=Available deployment --all --timeout=2m

kubectl apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: { name: selfsigned }
spec: { selfSigned: {} }
EOF
```

Then in [Step 5 (Install the chart)](#5-install-the-chart), drop the
`tls.existingSecret` flag and pass the cert-manager flags instead:

```bash
helm install warden ./deploy/helm/warden \
  -n warden \
  --set replicaCount=1 \
  --set seal.type=static \
  --set podDisruptionBudget.enabled=false \
  --set tls.certManager.enabled=true \
  --set tls.certManager.issuerRef.kind=ClusterIssuer \
  --set tls.certManager.issuerRef.name=selfsigned \
  --set storage.connectionUrl='postgres://warden:warden@warden-postgres:5432/warden?sslmode=disable' \
  --set seal.static.existingSecret=warden-seal \
  --set seal.static.keyId=dev-$(date +%Y%m%d)
```

### Rotation

cert-manager rotates the Secret in place before the cert expires. Warden
does **not** hot-reload TLS, so the new cert is not picked up until the
pod restarts. Trigger a rolling restart manually after each renewal:

```bash
kubectl rollout restart statefulset/warden -n warden
```

A future Warden release may add `SIGHUP`/fsnotify-based reload; until
then this step is unavoidable.

### Pod-startup race

When `tls.certManager.enabled=true`, the Certificate and StatefulSet are
created together. cert-manager typically writes the Secret within a few
seconds for in-cluster issuers (self-signed, CA, Vault PKI), low minutes
for ACME-HTTP01. The chart's startup probe gives 150s
(`failureThreshold: 30 × periodSeconds: 5`) before declaring the pod
failed, which absorbs the race for every issuer type we've tested. If
your issuer needs longer, bump `probes.startup.failureThreshold`.

---

## First-time initialization

On a fresh install, pods come up uninitialized: the `/v1/sys/health`
endpoint returns 501, the readiness probe fails, and the `warden` Service
has no endpoints. This is the intended state — Warden needs an operator
to run `sys/init` once to generate the root token and unseal keys.

### Why not auto-init?

The chart deliberately does not auto-run `sys/init`. The init response
contains the root token and unseal keys; auto-storing them in a Kubernetes
Secret is only safe if etcd is encrypted at rest, and the failure mode of
"chart-managed root token gets accidentally deleted with the release" is
catastrophic. Operators run init explicitly and store the response in
their own secrets-management system.

### Initialize the cluster

The headless Service has `publishNotReadyAddresses: true`, so you can
reach any pod directly even while readiness is failing:

```bash
kubectl -n warden port-forward pod/warden-0 8400:8400 &
PF_PID=$!

# secret_shares=1 / threshold=1 is convenient for dev; production should
# use Shamir splitting (e.g. 5 shares with a threshold of 3) so no single
# operator can recover or use the unseal keys alone.
curl -k -X POST https://127.0.0.1:8400/v1/sys/init \
  -H 'Content-Type: application/json' \
  -d '{"secret_shares": 1, "secret_threshold": 1}'

# Output:
# {
#   "root_token": "...",
#   "unseal_keys_b64": ["..."],
#   "unseal_keys_hex": ["..."]
# }

kill $PF_PID
```

Store `root_token` and `unseal_keys_b64` securely — they cannot be
recovered. With Transit auto-unseal the recovery shares only matter for
disaster recovery; with Shamir-only (no auto-unseal), you must collect
`threshold` shares for every restart.

For production deployments using auto-unseal, the remaining pods will
auto-unseal within ~10 seconds and become Ready. For the static-seal dev
profile, all pods share the same key so they also auto-unseal.

### Verify the cluster is healthy

```bash
kubectl -n warden get pods
# All pods should be Ready.

kubectl -n warden get endpoints warden
# Should list all pod IPs.

# Verify exactly one pod reports is_leader=true:
for i in 0 1 2; do
  kubectl -n warden exec warden-$i -- \
    curl -sk https://localhost:8400/v1/sys/leader | grep -o '"is_leader":[a-z]*'
done
```

---

## Upgrades

### Chart upgrades

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  -n warden -f your-values.yaml
```

The StatefulSet has `checksum/config` and (when present) `checksum/credentials`
pod annotations. Any change that affects the rendered ConfigMap or
chart-managed credentials Secret triggers a rolling restart bounded by
the PDB's `maxUnavailable: 1`: one pod at a time, the leader steps down
when its pod is replaced, and a standby is promoted within ~10s. There
is no client-visible downtime as long as `replicaCount >= 2`.

### Warden binary upgrades

Bump `image.tag` (or upgrade the chart whose `appVersion` advances):

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  -n warden --reuse-values \
  --set image.tag=v0.17.0
```

Same rolling-restart mechanics. Check release notes for any
configuration changes that require an HCL update first.

### Rotating the seal token (Transit auto-unseal)

Generate a new Vault token, update the operator-managed Secret, then roll
the pods so they pick up the new token:

```bash
kubectl -n warden patch secret warden-seal-token \
  -p '{"stringData":{"token":"hvs.NEW_TOKEN"}}'

kubectl -n warden rollout restart statefulset/warden
```

---

## Operations

### Sealing a single pod

```bash
kubectl -n warden exec warden-0 -- \
  curl -sk -X PUT https://localhost:8400/v1/sys/seal \
  -H "X-Warden-Token: $ROOT_TOKEN"
```

The pod will fail readiness immediately, be removed from the API Service,
and (with auto-unseal) re-unseal on its next reconciliation loop. Useful
for testing failover.

### Forcing a leader step-down

```bash
LEADER=$(kubectl -n warden get pods -l app.kubernetes.io/name=warden \
  -o name | head -1 | sed 's|pod/||')

kubectl -n warden exec "$LEADER" -- \
  curl -sk -X PUT https://localhost:8400/v1/sys/step-down \
  -H "X-Warden-Token: $ROOT_TOKEN"
```

A standby is promoted within ~10s.

### Increasing replica count

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  -n warden --reuse-values \
  --set replicaCount=5
```

New pods join the cluster as standbys after auto-unseal. No data
migration needed — everything is in Postgres.

---

## Cleanup

Tearing down a Warden install in the right order matters: the release
owns only the resources the chart rendered, while databases, TLS
Secrets, seal-token Secrets, and operator-created namespaces are
deliberately outside that scope so they survive `helm uninstall`. Deleting
them on purpose is straightforward; deleting them by accident is not
recoverable — especially the Postgres data and the seal token.

### Uninstalling the release

`helm uninstall` removes only the chart-rendered objects (StatefulSet,
Services, ConfigMap, ServiceAccount, PDB, and — when literal credentials
were passed via values — the chart-managed credentials Secret). The
namespace, operator-managed Secrets, and PostgreSQL are intentionally
left alone:

```bash
helm uninstall warden -n warden
```

Run `helm list -n warden` to confirm the release is gone. The
`warden-tls`, `warden-db` / `warden-postgres-creds`, and
`warden-seal-token` / `warden-seal` Secrets remain in the namespace.
That is intentional — reinstalling the chart against the same Postgres
and seal will pick the cluster back up without re-running `sys/init`.

### Dev cleanup (kind quickstart)

If you followed [Dev quickstart on kind](#dev-quickstart-on-kind), the
fastest reset is to delete the entire namespace and then the kind
cluster. There is no data worth keeping.

```bash
# Drops the release-owned resources, the dev Postgres StatefulSet and
# Service, every Secret (TLS, seal key, postgres creds), and any PVCs.
kubectl delete namespace warden

# Delete the kind cluster itself.
kind delete cluster --name warden

# Local files generated during the walkthrough.
rm -rf /tmp/warden-tls /tmp/warden-seal.key
```

Verify nothing is left:

```bash
kind get clusters       # should not list "warden"
kubectl config current-context  # may say "current-context is not set" — expected
```

### Production cleanup

For a production deployment the safe order is: uninstall the release,
**then** decide explicitly what stays:

```bash
helm uninstall warden -n warden
```

| Resource | Delete when… | How |
|---|---|---|
| `Secret/warden-tls` | retiring the listener cert | `kubectl -n warden delete secret warden-tls` |
| `Secret/warden-db` | retiring the Postgres database | `kubectl -n warden delete secret warden-db` |
| `Secret/warden-seal-token` | retiring the Transit unseal key. Deleting this without first re-keying via `sys/rekey` makes the data in Postgres permanently unreadable. | `kubectl -n warden delete secret warden-seal-token` |
| PostgreSQL database / instance | tearing down the install for good | Per your Postgres provider — `helm uninstall warden-db -n warden` for Bitnami, `kubectl delete cluster.postgresql.cnpg.io warden-db -n warden` for CloudNativePG, or your managed-database console. |
| Vault Transit unseal key | retiring the Transit key. Same data-loss caveat as the seal token. | `vault delete transit/keys/warden-unseal` (after a rotation/rekey, or as part of full decommission). |
| `Namespace/warden` | nothing else lives in this namespace | `kubectl delete namespace warden` |

If you want to redeploy later against the same data, stop after
`helm uninstall` and keep the Secrets and Postgres in place.

### Rolling back without uninstalling

To undo a chart upgrade without losing any state, use `helm rollback`:

```bash
helm history warden -n warden
helm rollback warden <revision> -n warden
```

This re-renders the previous chart values and triggers a rolling
restart bounded by the PDB. The cluster does not need to be sealed,
re-initialized, or re-keyed.

---

## Troubleshooting

### Pods stuck in `Running` but never `Ready`

Check the pod logs:

```bash
kubectl -n warden logs warden-0 --tail=50
```

Common causes:
- **Postgres unreachable** — verify the connection URL secret, network
  policies, and that `warden-postgres` is Ready.
- **Sealed forever, no auto-unseal** — for Transit, check that
  `seal.transit.address` is reachable from the pod and the token Secret
  is correct. For static seal, ensure the `current_key` Secret value is
  consistent across all pods.
- **Not initialized** — pods stay NotReady until `/v1/sys/init` runs. See
  [First-time initialization](#first-time-initialization).

### `helm install` fails immediately with a value error

The chart's preflight validator emits clear messages:

- `tls.existingSecret is required` — create a `kubernetes.io/tls` Secret.
- `Either storage.existingSecret or storage.connectionUrl must be set` —
  provide the postgres connection URL.
- `seal.transit.address is required when seal.type=transit` — Transit
  auto-unseal needs a Vault endpoint.
- `seal.type must be 'transit' or 'static'` — typo in `--set seal.type=`.

### TLS verification errors on `/v1/sys/init`

The `curl -k` flag in the init runbook disables certificate verification
because you typically use a self-signed cert for the API listener (the
cluster trusts it via the CA bundle). For client-side verification, pass
`--cacert ca.crt`.

### Standby pods not forwarding writes

The distroless Warden image has no shell or DNS tools, so verify the
headless Service is resolving from an ephemeral debug pod instead:

```bash
kubectl -n warden run dns-debug --rm -it --restart=Never \
  --image=busybox:1.36 -- \
  nslookup warden-0.warden-headless.warden.svc.cluster.local
```

If DNS fails, the `publishNotReadyAddresses` and per-pod-hostname behavior
of StatefulSets may be misconfigured by a cluster-wide DNS policy.

### Debugging inside the Warden container itself

When you need to inspect state *inside* a Warden pod — config files
mounted into `/config`, the working directory, the binary's view of
the filesystem — the production `nonroot` image is intentionally too
spare to help. Every release also publishes a sibling debug variant
at the same repository with a `-debug` suffix (and a moving `debug`
tag), built from the same binary on a base that bundles a BusyBox
shell. UID, GID, entrypoint, and the `/config` mount contract are
identical, so swapping in the debug tag is a pure image change with
no other values to adjust:

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.3 \
  -n warden --reuse-values \
  --set image.tag=v0.17.0-debug

kubectl -n warden exec warden-0 -- sh -c 'ls /config && id'
```

Roll back to the production tag (`--set image.tag=v0.17.0`, or
`--set image.tag=""` to fall back to the chart's `appVersion`)
once the investigation is done. The debug variant is meant for short-lived
diagnostic windows, not steady-state operation — it carries a
larger attack surface than the production image by design.

### `helm test` fails with connection_refused

The test pod hits the `warden` API Service. If no pods are Ready (e.g.
because init has not run yet), the Service has no endpoints and the curl
fails. Run `helm test` after the init flow completes.
