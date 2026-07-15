---
title: "operator"
---

Administrative operations on a Warden server. Today this groups a single
subcommand, `init`, which initializes a fresh server and generates the first root
token.

## Table of Contents

- [Usage](#usage)
- [`operator init`](#operator-init)
- [See Also](#see-also)

## Usage

```text
warden operator <subcommand> [options]
```

Global flags apply — see the [CLI overview](/cli/#global-flags).

## `operator init`

Initialize a new server. The root key is split into shares using Shamir's secret
sharing; a threshold of those shares is required to unseal. `init` prints the
unseal keys (and recovery keys, under auto-unseal) and the **root token** — once,
and never again. Store them securely.

**Usage:** `warden operator init [options]`

**Examples:**

```bash
# Default: 5 shares, threshold 3
warden operator init

# Custom shares and threshold
warden operator init --secret-shares=7 --secret-threshold=4

# PGP-encrypt each unseal key
warden operator init --pgp-keys="keybase:u1,keybase:u2,keybase:u3,keybase:u4,keybase:u5"

# Machine-readable output for IaC
warden operator init -o json
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--secret-shares` | `5` | Number of unseal key shares to generate. |
| `--secret-threshold` | `3` | Shares required to unseal. |
| `--pgp-keys` | *(none)* | Comma-separated PGP public keys (base64 or `keybase:user`) to encrypt the unseal keys. |
| `--root-token-pgp-key` | *(none)* | PGP public key to encrypt the root token. |
| `--stored-shares` | `0` | Shares to store (auto-unseal only). |
| `--recovery-shares` | `5` | Recovery key shares (auto-unseal only). |
| `--recovery-threshold` | `3` | Recovery shares required (auto-unseal only). |
| `--recovery-pgp-keys` | *(none)* | PGP keys to encrypt the recovery keys (auto-unseal only). |

After init, export the printed token so subsequent commands authenticate:

```bash
export WARDEN_TOKEN=<root-token>
warden status
```

## See Also

- [Seal / Unseal](/concepts/seal-unseal/) — the seal model and unseal flow.
- [High Availability](/concepts/high-availability/) — auto-unseal and recovery keys.
- [`warden status`](/cli/status/) — check initialization and seal state.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
