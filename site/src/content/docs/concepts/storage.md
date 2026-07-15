---
title: "Storage"
---

**Storage** is the durable backend where Warden persists its data. It is the one
piece of Warden that lives entirely outside the [barrier](/concepts/seal-unseal/): by the
time anything reaches storage it has already been encrypted, so the backend only
ever holds **ciphertext**.

## Storage Is Untrusted by Design

Warden treats its storage backend as untrusted. The [barrier](/concepts/seal-unseal/)
encrypts every value before it is written and decrypts it on the way back, so the
database (or whoever can read it) sees nothing but opaque blobs. A stolen storage
dump is worthless without the seal's key.

```
core/logical code  ─▶  barrier (encrypts)  ─▶  storage backend (ciphertext only)
```

Logical code never touches the backend directly. It goes through the barrier, and
through a **barrier view** — a prefix-scoped slice of the barrier, like a `chroot`
— so each [namespace](/concepts/namespaces/) and mount reads and writes only under its own
UUID-keyed prefix. That prefixing is what gives namespaces their hard storage
isolation.

## Supported Backends

A backend is selected by the `type` label of the [storage stanza](#configuring-storage):

| `type` | Use | Persistent | HA |
|--------|-----|-----------|----|
| `postgres` | Production | yes | yes |
| `inmem` | Dev / tests | **no** | no |
| `inmem_ha` | HA tests | no | yes |

**PostgreSQL is the production backend.** `inmem` keeps everything in memory and
loses it on exit — it is what the [dev server](/concepts/dev-server/) uses and is never
for production. `inmem_ha` exists only to exercise the HA code paths in tests.

## Configuring Storage

Storage is set in the server's HCL configuration with a `storage "<type>"`
stanza, and it is **required** — a production server will not start without one.
(The dev server skips this; `-dev` forces `inmem`.) Storage is fixed at startup;
there is no runtime command to change it.

```hcl
storage "postgres" {
  connection_url = "postgres://warden:password@db:5432/warden?sslmode=require"
  ha_enabled     = "true"
}
```

### PostgreSQL options

| Key | Purpose |
|-----|---------|
| `connection_url` | The Postgres DSN (required). Can be supplied out of band via the `WARDEN_PG_CONNECTION_URL` environment variable. |
| `table` | Table holding the encrypted key/value data. |
| `ha_table` | Table holding the [HA](/concepts/high-availability/) leader-election locks. |
| `ha_enabled` | `"true"` to enable active/standby HA on this backend. |
| `max_parallel` | Cap on concurrent operations against Postgres. |
| `max_idle_connections` | Idle size of the connection pool. |
| `max_connect_retries` | Retries while waiting for the database to come up at startup. |
| `skip_create_table` | `"true"` to skip automatic table creation (pre-provisioned or read-only databases). |

By default Warden creates its tables on first boot and verifies the server is a
supported PostgreSQL version. Writes are transactional (ACID), which Warden relies
on for atomic multi-key updates such as token persistence and credential
rotation.

## Storage and High Availability

High availability is a property of the storage backend. PostgreSQL is HA-capable:
with `ha_enabled = "true"`, nodes elect a leader through advisory locks in the
`ha_table`, using the database's own clock as the single source of truth. Warden
detects this capability automatically and runs active/standby when it is present.
See [High Availability](/concepts/high-availability/) for how the cluster behaves.

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier that encrypts everything before
  it reaches storage.
- [High Availability](/concepts/high-availability/) — leader election over the storage
  backend.
- [Namespaces](/concepts/namespaces/) — the per-namespace storage isolation prefixes.
- [Dev Server](/concepts/dev-server/) — the in-memory backend for local work.
