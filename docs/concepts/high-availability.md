# High Availability

A single Warden process is a single point of failure. **High availability (HA)**
runs several nodes against one shared [storage](storage.md) backend so that the
loss of any one node does not take the service down. One node is the **active
leader**; the others are **hot standbys** that take over automatically when the
leader fails.

## The Active/Standby Model

Warden HA is **single-active**: exactly one node serves requests at a time, and
the rest stand by. A standby does not read or write the barrier on its own —
it **forwards** requests to the active node and relays the response. This keeps
all writes funnelled through one node, which is what makes the model simple and
consistent (there is no multi-writer conflict to resolve).

All nodes share the same storage backend; HA is a property of that backend.
PostgreSQL is HA-capable, so a cluster is just several Warden nodes pointed at the
same database.

## Leader Election

Leadership is a **lock** in the database. With `ha_enabled` on the
[PostgreSQL](storage.md) backend, nodes contend for a single advisory lock (the
`ha_table`); whoever holds it is the active leader, and its identity and address
are recorded in the lock so the others can find it.

The lock is time-bound, using the **database's own clock** as the single source
of truth — so there is no dependence on the nodes' clocks agreeing:

- The leader **renews** the lock every few seconds.
- The lock **expires** about 15 seconds after the last renewal.
- A standby retries acquisition roughly once a second.

So if the leader stops renewing — it crashed, hung, or was partitioned away — the
lock expires and the first standby to grab it becomes the new leader. Writes are
additionally **fenced**: the active node validates that it still holds the lock on
every write, so a node that has lost leadership cannot keep writing (no
split-brain).

## Request Forwarding

A standby forwards almost everything to the active node over an **mTLS reverse
proxy**. A short list of status endpoints — health, readiness, leader, seal
status, init — is served locally; every other request is forwarded.

The standby learns where to send by reading the active node's advertisement: its
client address (`api_addr`), its cluster address (`cluster_addr`), and the
cluster certificate to authenticate the connection. If forwarding fails — the
leader is unreachable or has changed — the standby falls back to a **307 redirect**
pointing the client at the current leader. Standbys refresh their view of the
leader every couple of seconds, so they re-point quickly after a failover.

## Failover

Failover is automatic and needs no operator:

1. The active node stops renewing the lock (crash, hang, or partition).
2. The lock expires (≤ ~15 seconds).
3. A standby acquires it, runs its post-unseal startup, **promotes** itself to
   active, and advertises its address and cluster certificate.
4. The other standbys notice the change on their next refresh and forward to the
   new leader.

In the best case a standby is promoted within a second or two of the lock coming
free; the worst case is bounded by the lock TTL.

## Only Unsealed Nodes Lead

A **sealed** node will not contend for the lock — it cannot serve requests, so it
must never become leader. This guarantees the active node is always one that can
actually do work, and it is why **[auto-unseal](seal-unseal.md) matters for HA**:
a standby has to be unsealed to be promotable, so for failover to be automatic,
every node must unseal itself on startup without a human. A cluster built on
Shamir (no auto-unseal) cannot fail over unattended.

## Cluster Communication

Nodes talk to each other over a dedicated **cluster listener** on `cluster_addr`,
separate from the client API. The connection is mutually authenticated with a
cluster certificate that Warden **generates itself** — a fresh self-signed
identity per leadership term — and the active node advertises it to the standbys.
There is no external PKI to manage: enable the cluster address and Warden handles
the inter-node TLS.

## Configuration

An HA node needs three things: its own two addresses and an HA-enabled storage
backend.

```hcl
api_addr     = "https://node-a.example.com:8400"   # client-facing, advertised to standbys
cluster_addr = "https://node-a.example.com:8401"   # inter-node mTLS

storage "postgres" {
  connection_url = "postgres://warden:password@db:5432/warden?sslmode=require"
  ha_enabled     = "true"
}
```

- **`api_addr`** — the address clients use, which the leader advertises so
  standbys can redirect to it.
- **`cluster_addr`** — the inter-node address the cluster listener binds for mTLS
  forwarding.
- **`ha_enabled`** on the storage stanza turns on leader election; `ha_table`
  names the lock table.

Each node sets its own `api_addr`/`cluster_addr` and points at the shared
database. Warden detects HA capability automatically and runs active/standby;
`disable_clustering = true` opts out even when the backend supports it.

## Observing the Cluster

To find the active node and a node's role:

```bash
warden status      # reports is_leader and leader_address
```

backed by `sys/leader` (`ha_enabled`, `is_leader`, `leader_address`, and the
active node's `active_time`) and the `ha_enabled` field of `sys/seal-status`.

## Step-Down

The active node can be told to **relinquish leadership** on demand via the
`sys/step-down` endpoint — it releases the lock, a standby is promoted, and the
former leader rejoins as a standby (pausing briefly before contending again).
This is the graceful way to drain a node for maintenance without waiting for a
lock to time out.

## See Also

- [Storage](storage.md) — the shared backend and the `ha_enabled` lock table.
- [Seal and Unseal](seal-unseal.md) — why auto-unseal is required for unattended
  failover.
- [Architecture](../architecture.md) — where HA sits in the overall design.
