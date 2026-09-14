---
title: "The Warden Helm Chart"
description: "Chart reference for the first-party Warden Helm chart: installation methods, values, versioning, upgrades, rollback, and uninstall semantics."
sidebar:
  label: Helm
  order: 4
---

Warden publishes a first-party Helm chart at
[`deploy/helm/warden/`](https://github.com/stephnangue/warden/tree/main/deploy/helm/warden/).
This page is the chart reference — where to get it, which values matter, and what
`upgrade`, `rollback`, and `uninstall` actually do.

For the end-to-end deployment story — PostgreSQL, TLS, auto-unseal, first-time
initialization, and day-2 runbooks — see
[Deploying Warden on Kubernetes](/install/kubernetes/).

- [Installing the chart](#installing-the-chart)
- [Chart version vs Warden version](#chart-version-vs-warden-version)
- [Values reference](#values-reference)
- [Upgrading the release](#upgrading-the-release)
- [Rolling back](#rolling-back)
- [Uninstalling](#uninstalling)
- [Troubleshooting the chart](#troubleshooting-the-chart)

---

## Installing the chart

The chart is published to the GitHub Container Registry on every release tag, as
an OCI artifact alongside the Warden container image. Pick the method that
matches your environment.

### From the OCI registry (recommended)

Helm 3.8+ pulls OCI charts natively — no `helm repo add` needed:

```bash
helm install warden oci://ghcr.io/stephnangue/charts/warden \
  -n warden --create-namespace \
  -f your-values.yaml
```

Without `--version`, Helm resolves the latest published chart. See
[Chart version vs Warden version](#chart-version-vs-warden-version) for when to
pin instead.

### From a release tarball (air-gapped)

For clusters that cannot reach OCI registries — for example, those restricted to
an internal mirror — every release also attaches the chart tarball to its GitHub
Release page:

```bash
VERSION=$(curl -fsSL https://api.github.com/repos/stephnangue/warden/releases/latest \
  | grep '"tag_name"' | cut -d'"' -f4)                # e.g. v0.20.0
CHART_VERSION=$(helm show chart oci://ghcr.io/stephnangue/charts/warden \
  | awk '/^version:/{print $2}')                      # e.g. 0.3.6

curl -L -o warden-chart.tgz \
  "https://github.com/stephnangue/warden/releases/download/${VERSION}/warden-${CHART_VERSION}.tgz"

helm install warden ./warden-chart.tgz \
  -n warden --create-namespace \
  -f your-values.yaml
```

Run the two lookups from a connected machine and carry the tarball across.

### From the source repo (development)

For chart development, or to install an unreleased version:

```bash
git clone https://github.com/stephnangue/warden
helm install warden ./warden/deploy/helm/warden \
  -n warden --create-namespace \
  -f your-values.yaml
```

The source tree also carries `values-dev.yaml`, a single-replica profile for kind
or minikube — see the
[dev quickstart](/install/kubernetes/#dev-quickstart-on-kind).

### Starting from the chart's own defaults

```bash
helm show values oci://ghcr.io/stephnangue/charts/warden > your-values.yaml
```

---

## Chart version vs Warden version

Two independent version numbers, and the leading `v` belongs to exactly one
of them.

| | What it is | Where it comes from |
|---|---|---|
| `--version` | The **chart** version | `Chart.yaml: version`. Bumped when the templates change. |
| `image.tag` | The **Warden binary** version | Defaults to `"v" + .Chart.AppVersion`. The release pipeline sets `appVersion` to the git tag with its `v` stripped. |

:::note[`image.tag` needs the `v`; `--version` must not have it]
The StatefulSet template prepends `v` to `appVersion`, so `appVersion: "0.20.0"`
resolves to `ghcr.io/stephnangue/warden:v0.20.0`. If you set `image.tag`
yourself, carry the `v` — `--set image.tag=v0.20.0`. Chart versions never take
one: `--version 0.3.6`.
:::

The install commands on this page leave both numbers unpinned so they stay
correct as releases land. Look up the current values when you need them:

```bash
helm show chart oci://ghcr.io/stephnangue/charts/warden
# version:    the chart version, for --version
# appVersion: the Warden version; the image tag is this with a "v" prefix
```

:::caution[Pin in CI and GitOps]
An unpinned `helm install` or `helm upgrade` resolves to whatever is newest at
apply time, which makes a pipeline non-reproducible and can roll a cluster onto
a new Warden binary nobody chose. Write both numbers out as literals in anything
automated:

```bash
helm install warden oci://ghcr.io/stephnangue/charts/warden \
  --version 0.3.6 \
  --set image.tag=v0.20.0 \
  -n warden --create-namespace -f your-values.yaml
```

Resolving them with `helm show chart` at apply time is not pinning — it is the
same moving target, one command further away. Run that lookup by hand, commit
the numbers it prints, and bump them deliberately.
:::

---

## Values reference

The full set is in
[`values.yaml`](https://github.com/stephnangue/warden/blob/main/deploy/helm/warden/values.yaml),
which is commented. The values below are the ones most deployments touch.

### Required input

Every install must resolve three things: where the data lives, how the barrier
key is protected, and what certificate the listener serves.

| Value | Notes |
|---|---|
| `storage.existingSecret` | Secret holding the full `postgres://` URL under `storage.connectionUrlKey` (default `connection_url`). Recommended. |
| `storage.connectionUrl` | Literal URL instead. The chart creates its own Secret. Avoid in production — values files are rarely encrypted. |
| `seal.type` | `transit` (default) or `static`. Transit auto-unseals on every restart; static requires manual unseal. |
| `seal.transit.address` / `.keyName` | Both required when `seal.type=transit`. |
| `seal.transit.existingSecret` | Secret holding the Vault token under `seal.transit.tokenKey` (default `token`). A literal `seal.transit.token` works instead — avoid in production. One of the two is required. |
| `seal.static.existingSecret` / `.keyId` | Required when `seal.type=static`. The Secret's `current_key` is projected to `/seal/key`. |
| `tls.existingSecret` | A `kubernetes.io/tls` Secret, optionally with `ca.crt`. |
| `tls.certManager.enabled` | Alternative to `tls.existingSecret` — mutually exclusive, preflight rejects both. |

### Commonly overridden

| Value | Default | Notes |
|---|---|---|
| `replicaCount` | `3` | HA election runs on PostgreSQL advisory locks, so any count works — there is no quorum to satisfy. |
| `image.tag` | `""` → `v<appVersion>` | Pin a Warden binary independently of the chart. |
| `resources` | 100m CPU / 256Mi request, 512Mi limit | Raise for high-throughput deployments. |
| `topologySpreadConstraints` | one zone constraint, `ScheduleAnyway` | Tighten to `DoNotSchedule` when you have guaranteed multi-zone capacity. |
| `podDisruptionBudget.enabled` | `true`, `maxUnavailable: 1` | Bounds voluntary disruption during drains and rolling upgrades. |
| `tls.requireClientCert` | `false` | Set `true` for mTLS on the API listener; clients must present a cert signed by the CA in `ca.crt`. |
| `audit.enabled` / `audit.filePath` | `true`, `/var/log/warden/audit.log` | Mounted as an `emptyDir`. Swap for a PVC if audit logs must survive restarts. |
| `logLevel` / `logFormat` | `info` / `json` | |
| `ipBindingPolicy` | `optional` | `disabled`, `optional`, or `required`. |
| `probes.startup.failureThreshold` | `30` (× 5s = 150s) | Raise if your certificate issuer is slow — see [the pod-startup race](/install/kubernetes/#pod-startup-race). |
| `extraEnv` | `[]` | Extra variables for `{{ env "..." }}` placeholders in the HCL. |

### TLS (`tls.*`)

Warden requires TLS on the API listener. Supply your own Secret, or let
cert-manager issue and rotate one. With `tls.certManager.enabled=true` the chart
renders a `Certificate` and these defaults apply:

| Field | Default |
|---|---|
| `secretName` | `{fullname}-tls` (override with `tls.certManager.secretName`) |
| `dnsNames` | `{fullname}`, `{fullname}.{ns}.svc`, `{fullname}.{ns}.svc.cluster.local`, `*.{fullname}-headless.{ns}.svc.cluster.local` |
| `duration` / `renewBefore` | `2160h` (90d) / `360h` (15d) |
| `privateKey` | ECDSA P-256, `rotationPolicy: Always` |
| `usages` | `[server auth]`, plus `client auth` when `tls.requireClientCert=true` |

`tls.certManager.issuerRef.name` is required. The chart does **not** create the
`Issuer` — that is environment policy and typically lives elsewhere. See
[Streamlined TLS with cert-manager](/install/kubernetes/#streamlined-tls-with-cert-manager).

### Security context

The defaults mirror the distroless base and rarely need changing:
`runAsNonRoot: true`, UID/GID/fsGroup `65532`, `seccompProfile: RuntimeDefault`,
`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and all
capabilities dropped.

---

## Upgrading the release

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  -n warden -f your-values.yaml
```

To move the Warden binary without changing the chart:

```bash
helm upgrade warden oci://ghcr.io/stephnangue/charts/warden \
  -n warden --reuse-values \
  --set image.tag=v0.20.0
```

Both trigger the same rolling restart. For what that restart does to a live
cluster — and when it is safe — see
[Upgrades](/install/kubernetes/#upgrades).

Check the [upgrade guides](/upgrade/from-v0-19/) before moving a server binary
across a release that changes configuration or policy syntax.

---

## Rolling back

To undo a chart upgrade without losing state:

```bash
helm history warden -n warden
helm rollback warden <revision> -n warden
```

This re-renders the previous values and triggers a rolling restart bounded by the
PodDisruptionBudget. The cluster does not need to be sealed, re-initialized, or
re-keyed — all state lives in PostgreSQL, which the chart never touches.

---

## Uninstalling

```bash
helm uninstall warden -n warden
```

The release owns only what the chart rendered: the StatefulSet, both Services,
the ConfigMap, the ServiceAccount, the PodDisruptionBudget, the `Certificate`
when cert-manager is enabled, and — only when literal credentials were passed via
values — the chart-managed credentials Secret.

Everything else is deliberately outside that scope and survives:

- the namespace
- operator-managed Secrets (`warden-tls`, `warden-db`, `warden-seal-token`)
- PostgreSQL and its data
- the Vault Transit key

That is what makes a reinstall against the same database and seal pick the
cluster back up without re-running `sys/init`. For deleting those on purpose, in
the right order, see
[Production cleanup](/install/kubernetes/#production-cleanup).

---

## Troubleshooting the chart

### `helm install` fails immediately with a value error

The chart's preflight validator emits the specific message:

- `tls.existingSecret is required` — create a `kubernetes.io/tls` Secret, or
  enable `tls.certManager`.
- `Either storage.existingSecret or storage.connectionUrl must be set` — provide
  the PostgreSQL connection URL.
- `seal.transit.address is required when seal.type=transit` — Transit auto-unseal
  needs a Vault endpoint.
- `seal.type must be 'transit' or 'static'` — typo in `--set seal.type=`.

Setting both `tls.existingSecret` and `tls.certManager.enabled=true` is also
rejected; pick one.

### `helm test` fails with connection_refused

The test pod hits the `warden` API Service. If no pods are Ready — commonly
because [initialization](/install/kubernetes/#first-time-initialization) has not
run yet — the Service has no endpoints and the request fails. Run `helm test`
after the init flow completes.

### Pods start but never become Ready

That is a deployment problem rather than a chart problem — see
[Troubleshooting](/install/kubernetes/#troubleshooting).
