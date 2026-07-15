---
title: "server"
---

Start a Warden server that responds to API requests. In production the server is
driven by an HCL configuration file (or a directory of them); a `--dev` flag spins
up a throwaway, pre-unsealed instance for local work.

## Usage

```text
warden server [options]
```

A configuration source is required unless `--dev` is set: pass `-c/--config` for a
single file or `--config-dir` for a directory.

## Configuration files

```bash
# Single configuration file
warden server --config=/etc/warden/config.hcl

# Merge every .hcl file in a directory (lexical order; later files win — useful
# for splitting a ConfigMap and a Secret in Kubernetes)
warden server --config-dir=/etc/warden/conf.d
```

Config files may reference environment variables via `{{ env "VAR_NAME" }}`.
`--config` and `--config-dir` are mutually exclusive.

## Dev mode

`--dev` starts an in-memory server that auto-initializes and auto-unseals — no
config file, no persistence. It prints a root token and an unseal key on startup.
Dev mode always uses `inmem` storage, so `--config`/`--config-dir` cannot be
combined with it. See [Dev Server](/concepts/dev-server/).

```bash
warden server --dev
warden server --dev --dev-root-token=root
warden server --dev --dev-tls          # self-signed TLS listener
```

## Flags

**Configuration**

| Flag | Default | Description |
|---|---|---|
| `-c`, `--config` | *(none)* | Path to a configuration file. |
| `--config-dir` | *(none)* | Path to a directory of `.hcl` files, merged in lexical order. |

**Dev mode**

| Flag | Default | Description |
|---|---|---|
| `--dev` | `false` | Enable dev mode: inmem storage, auto-init, auto-unseal. |
| `--dev-root-token` | *(none)* | Custom root token for dev mode (requires `--dev`). |
| `--dev-tls` | `false` | Enable TLS on the dev listener (auto-generates a self-signed cert). |
| `--dev-tls-cert-file` | *(none)* | TLS certificate file for dev mode (implies `--dev-tls`). |
| `--dev-tls-key-file` | *(none)* | TLS private key file for dev mode (paired with the cert file). |
| `--dev-tls-ca-cert-file` | *(none)* | CA certificate for verifying client certs in dev mode. |
| `--dev-tls-require-client-cert` | `false` | Require client certificates (needs `--dev-tls-ca-cert-file`). |
| `--dev-tls-spiffe` | `false` | Serve dev TLS using a SPIFFE Workload API X509-SVID (auto-rotating). |
| `--dev-tls-spiffe-socket` | `$SPIFFE_ENDPOINT_SOCKET` | Workload API socket for `--dev-tls-spiffe`. |

The dev-TLS flags require `--dev`. The SPIFFE serving mode is mutually exclusive
with the file-based dev-TLS flags.

## See Also

- [Dev Server](/concepts/dev-server/) — what dev mode sets up and its limits.
- [Storage](/concepts/storage/) — production storage backends.
- [Seal / Unseal](/concepts/seal-unseal/) — initialization and unsealing.
- [High Availability](/concepts/high-availability/) — clustering and HA configuration.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
