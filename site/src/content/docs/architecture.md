---
title: "Architecture"
---

Warden is a Go service that sits between workloads and providers. A [provider](/concepts/providers/) is a mounted backend that proxies a workload's request to an upstream service — authenticating the caller, checking [policy](/concepts/policies/), and injecting a [credential](/concepts/credentials/) on the way through. The workload talks to Warden as if it were the upstream and never holds the upstream secret.

**Key design decisions:**
- **Seal/unseal model** — Warden protects secrets at rest with envelope encryption behind a barrier. A running server unseals itself at startup from an auto-unseal seal (Transit, AWS/GCP/Azure/OCI KMS, PKCS#11, KMIP, or a static key); `shamir` is the default seal type and splits the key into shares. Dev mode uses an in-memory seal. See [Seal and Unseal](/concepts/seal-unseal/).
- **Access brokering** — Warden holds the privileged upstream secret and injects a scoped, often short-lived [credential](/concepts/credentials/) into each proxied request, so workloads reach upstreams without ever holding long-lived keys.
- **Active/standby HA** — See [High Availability](#high-availability) below.
- **Namespace isolation** — Every credential source, policy, and mount point is scoped to a [namespace](/concepts/namespaces/) with hard boundaries. Policies cannot leak across namespaces.

## High Availability

Warden supports active/standby HA. Multiple nodes share the same storage backend and use PostgreSQL advisory locks for leader election. One node becomes the active leader; the rest are hot standbys that automatically promote on leader failure.

**How it works:**

- **Standby forwarding** — Standby nodes forward all write and read requests to the active leader via mTLS reverse proxy. Clients can send requests to any node; the response is the same regardless of which node receives it.
- **Automatic failover** — If the leader fails, a standby acquires the lock and promotes itself. Standby nodes detect the leader change and redirect their forwarding proxy to the new leader.
- **Sealed node protection** — Sealed nodes are prevented from acquiring the leadership lock, ensuring only fully operational nodes can become leader.

**Configuration** — each node needs `api_addr` (its own API address, used by the leader to advertise itself), `cluster_addr` (its mTLS cluster address for inter-node communication), and a shared storage backend with `ha_enabled`:

```hcl
api_addr     = "http://10.0.1.1:8400"
cluster_addr = "https://10.0.1.1:8401"

storage "postgres" {
  connection_url = "postgres://warden:password@db:5432/warden?sslmode=require"
  table          = "warden_store"
  ha_table       = "warden_ha_locks"
  ha_enabled     = "true"
}

listener "tcp" {
  address     = "0.0.0.0:8400"
  tls_disable = true
}
```

## Configuration

Warden uses HCL configuration files. See `deploy/config/warden.local.hcl` for a full example covering storage backend, listener, providers, and auth methods.

The listener stanza follows the `tls_disable` convention: TLS is on by default and the listener requires both `tls_cert_file` and `tls_key_file`. Set `tls_disable = true` to run plain HTTP (intended for loopback dev work).

Unknown top-level attributes and blocks — and unknown attributes inside known blocks — are dropped at parse time with a startup warning on stderr rather than rejected. This lets operators drop in a foreign-style config (`ui = true`, `cluster_name = "..."`, `service_registration "consul" { ... }`, and similar) without manual cleanup; the warning surfaces typos so they do not pass silently.
