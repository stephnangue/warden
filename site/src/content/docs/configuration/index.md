---
title: "Configuration"
---

A production Warden server is driven by an **HCL configuration file** — or a
directory of them, merged in order. The file declares the server's [storage
backend](/configuration/storage/), one or more [listeners](/configuration/listener/),
the [seal](/configuration/seal/) that guards the barrier, any startup [audit
devices](/configuration/audit/), and a set of top-level parameters covering
logging, cluster addressing, and rotation bounds.

This section is the key-by-key reference for that file. See
[`warden server`](/cli/server/) for how the server is launched and
[Concepts](/concepts/) for the ideas each stanza builds on.

## Loading configuration

Point the server at a single file or a directory:

```bash
# One file
warden server --config=/etc/warden/config.hcl

# Every .hcl file in a directory, merged in lexical order (later files win —
# useful for splitting a ConfigMap and a Secret in Kubernetes)
warden server --config-dir=/etc/warden/conf.d
```

`--config` and `--config-dir` are mutually exclusive, and one of them is required
unless the server is started with `--dev` (see [Dev Server](/concepts/dev-server/)).
When a directory is merged, later files override earlier ones and block stanzas
are replaced wholesale.

Unknown attributes and blocks are dropped rather than rejected, so a newer config
stays loadable on an older binary; the server logs a warning for each one it
ignores.

## Environment variables

Config files are run through a template pass before they are parsed, exposing a
single `env` function so any value can reference an environment variable:

```hcl
api_addr = "https://{{ env "POD_NAME" }}.warden-headless.{{ env "POD_NAMESPACE" }}.svc.cluster.local:8400"
```

The `{{ env "VAR" }}` syntax is used in preference to `${VAR}` so it does not
collide with HCL's own `${...}` interpolation, which is left untouched. A missing
variable expands to the empty string, matching shell semantics. This is the
recommended way to keep secrets out of the file — for example the Postgres DSN can
be supplied out of band via the `WARDEN_PG_CONNECTION_URL` environment variable
instead of `connection_url`.

## A minimal configuration

```hcl
log_level = "info"

storage "postgres" {
  connection_url = "postgres://warden:password@db:5432/warden?sslmode=require"
}

listener "tcp" {
  address       = ":8400"
  tls_cert_file = "/certs/warden-cert.pem"
  tls_key_file  = "/certs/warden-key.pem"
}
```

With no `seal` stanza the server uses the [`shamir`](/configuration/seal/#shamir)
seal, which requires operators to supply unseal keys at startup. Configure an
[auto-unseal seal](/configuration/seal/) for any unattended deployment.

## General parameters

These are set at the top level of the file, outside any block.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `log_level` | `info` | Log verbosity: `trace`, `debug`, `info`, `warn`, `error`. |
| `log_format` | `standard` | `standard` or `json`. |
| `log_file` | *(stderr)* | Path to write logs to instead of standard error. |
| `log_rotation_period` | `0` | Rotate the log file after this many hours (`0` disables time-based rotation). |
| `log_rotate_megabytes` | `0` | Rotate the log file once it reaches this size in MB (`0` disables size-based rotation). |
| `log_rotate_max_files` | `0` | Number of rotated log files to retain (`0` keeps all). |
| `api_addr` | *(none)* | Address advertised to clients for API requests. Standby nodes redirect clients here on the active node. **Required when HA is enabled.** |
| `cluster_addr` | *(none)* | Address for inter-node cluster communication. Must be an `https://` URL with a host; a dedicated cluster listener with auto-generated mTLS is started on it. **Required when HA is enabled.** |
| `disable_clustering` | `false` | Disable HA clustering even if the storage backend supports it. |
| `ip_binding_policy` | `optional` | How client-IP binding is enforced for tokens: `disabled`, `optional` (check only when both creation and request IPs are present), or `required`. |
| `min_cred_source_rotation_period` | *(none)* | Lower bound on the rotation period a credential source may request (Go duration, e.g. `24h`). |
| `max_cred_source_rotation_period` | *(none)* | Upper bound on a credential source's rotation period. Must be ≥ the minimum. |
| `min_cred_spec_rotation_period` | *(none)* | Lower bound on the rotation period a credential spec may request (Go duration, e.g. `1h`). |
| `max_cred_spec_rotation_period` | *(none)* | Upper bound on a credential spec's rotation period. Must be ≥ the minimum. |

## High-availability tuning

These parameters tune the [HA cluster](/concepts/high-availability/) — leader
election, step-down, and inter-node forwarding. All values are Go duration
strings (e.g. `30s`, `1h`); omitting one uses the built-in default shown below.
Most deployments never need to change them.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `goroutine_shutdown_timeout` | `30s` | Max time to wait for background goroutines to exit during step-down. |
| `lock_acquisition_timeout` | `0` | Max time to wait when acquiring the HA lock. `0` waits indefinitely. |
| `leader_cleanup_interval` | `1h` | How often the active node clears stale leader advertisements from storage. |
| `step_down_state_lock_timeout` | `30s` | Max time to acquire the state lock during step-down before forcing teardown. |
| `leader_lookup_timeout` | `10s` | Deadline for barrier reads when looking up the leader advertisement. |
| `clock_skew_grace` | `1m` | Backwards offset on cluster-certificate `NotBefore` to tolerate clock drift between nodes. |
| `cluster_listener_read_timeout` | `30s` | HTTP read timeout for the cluster listener (inter-node forwarding). |
| `cluster_listener_write_timeout` | `1m` | HTTP write timeout for the cluster listener. |
| `forwarding_timeout` | `1m` | Max time for a request forwarded from a standby to the active node. |

## Configuration stanzas

| Stanza | Purpose |
|--------|---------|
| [`listener`](/configuration/listener/) | Where and how the server accepts API traffic (TLS, SPIFFE). |
| [`storage`](/configuration/storage/) | The durable backend the barrier encrypts into. |
| [`seal`](/configuration/seal/) | The mechanism that guards the barrier's root key. |
| [`audit`](/configuration/audit/) | Audit devices registered at startup. |

## See Also

- [`warden server`](/cli/server/) — the flags that pass a config file or directory.
- [Concepts](/concepts/) — the ideas behind each stanza.
- [High Availability](/concepts/high-availability/) — clustering and the tuning parameters above.
