# Architecture

Warden is a Go service that sits between workloads and providers. Providers are registered as either streaming backends (which proxy traffic to upstream services) or access backends (which vend credentials directly without proxying). Each backend has its own credential source driver, authentication flow, and policy rules.

**Key design decisions:**
- **Seal/unseal model** — Like Vault, Warden protects secrets at rest using envelope encryption. Supports dev mode (in-memory) and production mode with multiple seal types (Shamir, Transit, AWS KMS, GCP KMS, Azure Key Vault, OCI KMS, PKCS11, KMIP) and PostgreSQL storage.
- **Active/standby HA** — See [High Availability](#high-availability) below.
- **Access grants over proxying for databases** — For providers like RDS where Warden doesn't need to sit in the data path, access backends return ready-to-use connection strings with short-lived tokens. This avoids the latency and complexity of proxying database traffic while preserving identity-based access control and audit attribution.
- **Namespace isolation** — Every credential source, policy, and mount point is scoped to a namespace with hard boundaries. Policies cannot leak across namespaces.

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
  tls_enabled = false
}
```

## Configuration

Warden uses HCL configuration files. See `deploy/config/warden.local.hcl` for a full example covering storage backend, listener, providers, and auth methods.
