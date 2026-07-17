---
title: "Storage"
---

> Server config stanza: `storage "<type>"`

The `storage` stanza selects the durable backend where Warden persists its data.
Exactly one is declared, and it is **required** — a production server will not
start without one. Storage is fixed at startup; there is no runtime command to
change it. Everything written here is already encrypted by the
[barrier](/concepts/seal-unseal/), so the backend only ever holds ciphertext — see
[Storage](/concepts/storage/) for why it is treated as untrusted.

```hcl
storage "postgres" {
  connection_url = "postgres://warden:password@db:5432/warden?sslmode=require"
  ha_enabled     = "true"
}
```

## Supported backends

| `type` | Use | Persistent | HA |
|--------|-----|------------|----|
| `postgres` | Production | yes | yes |
| `inmem` | Dev / tests | **no** | no |
| `inmem_ha` | HA tests | no | yes |

**PostgreSQL is the production backend.** `inmem` keeps everything in memory and
loses it on exit — it is what the [dev server](/concepts/dev-server/) uses and is
never for production. `inmem_ha` exists only to exercise the HA code paths in
tests.

## PostgreSQL

| Key | Default | Description |
|-----|---------|-------------|
| `connection_url` | *(required)* | The Postgres DSN. Can be supplied out of band via the `WARDEN_PG_CONNECTION_URL` environment variable. |
| `table` | `warden_kv_store` | Table holding the encrypted key/value data. |
| `ha_table` | `warden_ha_locks` | Table holding the [HA](/concepts/high-availability/) leader-election locks. |
| `ha_enabled` | `false` | `"true"` to enable active/standby HA on this backend. |
| `max_parallel` | `128` | Cap on concurrent operations against Postgres. |
| `max_idle_connections` | *(driver default)* | Idle size of the connection pool. |
| `max_connect_retries` | *(none)* | Retries while waiting for the database to come up at startup. |
| `skip_create_table` | `false` | `"true"` to skip automatic table creation (pre-provisioned or read-only databases). |

By default Warden creates its tables on first boot and verifies the server is a
supported PostgreSQL version. Writes are transactional (ACID), which Warden relies
on for atomic multi-key updates such as token persistence and credential
rotation. Set `ha_enabled = "true"` for a clustered deployment — nodes then elect
a leader through advisory locks in the `ha_table`, using the database's clock as
the single source of truth.

## In-memory backends

`inmem` and `inmem_ha` take no configuration:

```hcl
storage "inmem" {}
```

Both keep all data in process memory and lose it on exit. Use them only for local
development and tests, never for a real deployment.

## See Also

- [Storage](/concepts/storage/) — why the backend is untrusted, and the barrier that encrypts every value.
- [Seal and Unseal](/concepts/seal-unseal/) — the barrier itself.
- [High Availability](/concepts/high-availability/) — leader election over the storage backend.
