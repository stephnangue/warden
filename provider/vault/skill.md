---
name: vault
description: "Call HashiCorp Vault / OpenBao through Warden — read secrets, sign, encrypt, manage PKI — without ever holding a Vault token."
category: provider-guide
provider: vault
requires: []
upstream: HashiCorp Vault / OpenBao
---

# Vault through Warden

## What it does

Warden proxies Vault HTTP API requests. The agent sends a normal
Vault request to a Warden URL; Warden authenticates the agent
(JWT or cert), mints a short-lived Vault token from the configured
credential spec, injects it as `X-Vault-Token`, and forwards.
The agent **never holds a Vault token**.

## Configure the CLI/SDK

`<gateway-url>` is the `url` of the role you chose, as returned by the
`list_roles` discovery tool. Prepend `$WARDEN_ADDR` (the address you already
used to discover your roles). Each role has its own `url`: to act under a
*different* role, use that role's `url`.

Present your identity on every call: `Authorization: Bearer <jwt>` (Vault also
accepts the JWT in `X-Vault-Token`), or an mTLS client certificate. A `401`
means the JWT expired (typical TTL 5–60 min) — refresh and retry.

```bash
URL pattern : $WARDEN_ADDR<gateway-url><vault-api-path>
Auth header : Authorization: Bearer <jwt>  # OR X-Vault-Token: <jwt>
```

### Vault / OpenBao CLI

The Vault CLI works against Warden unchanged — point it at the
Warden gateway and use the JWT as the Vault token. Warden detects
the JWT prefix in `X-Vault-Token` and treats it as identity.

**Use whichever binary the environment has.** OpenBao ships its CLI
as `bao` (a fork of `vault`); some environments install one, some
the other, some both. The two are command-compatible — pick the one
on `PATH`. Probe order:

```bash
if command -v vault >/dev/null; then CLI=vault
elif command -v bao >/dev/null; then CLI=bao
else echo "neither vault nor bao is installed" >&2; exit 1
fi
```

Both honour `VAULT_ADDR` + `VAULT_TOKEN` (yes, `bao` reads
`VAULT_*` env vars too):

```bash
export VAULT_ADDR="$WARDEN_ADDR<gateway-url>"
export VAULT_TOKEN="<jwt>"

$CLI kv get secret/myapp/config
$CLI kv put secret/myapp/config foo=bar
$CLI list secret/myapp/
$CLI write pki/sign/server-tpl csr=@./req.csr
```

The agent never holds a real Vault token; the JWT is the identity.

### Vault SDK

For the official Go / Python / Node Vault SDKs, the same shape: set
the client's `Address` to `$WARDEN_ADDR<gateway-url>`
and its `Token` to the JWT.

### Raw HTTP (curl)

```bash
curl -H "Authorization: Bearer <jwt>" \
  "$WARDEN_ADDR<gateway-url>v1/secret/data/myapp/config"
```

## Examples

(Examples use a concrete `<gateway-url>` of `/v1/vault/role/secrets-reader/gateway/`;
substitute your role's `url`. `VAULT_ADDR` and
`VAULT_TOKEN` are exported as shown above.)

KV v2 read:
```bash
vault kv get secret/app/db
```

KV v2 write (operator-permitted):
```bash
vault kv put secret/app/db key=value
```

Cross-namespace reads (Vault Enterprise / OpenBao namespaces — pass
the upstream namespace via `VAULT_NAMESPACE`, distinct from Warden's
namespace):
```bash
VAULT_NAMESPACE=prod vault kv get secret/app/db
```

PKI sign:
```bash
vault write pki/sign/server-tpl csr=@./req.csr
```

Same operations via raw HTTP for scripting:
```bash
curl -H "Authorization: Bearer <jwt>" \
  $WARDEN_ADDR/v1/vault/role/secrets-reader/gateway/v1/secret/data/app/db
```

## Quirks

- **`/v1` is auto-prepended.** A request to `…/gateway/secret/data/foo`
  is rewritten to `…/secret/data/foo` upstream as if you'd written
  `…/gateway/v1/secret/data/foo`. Either form works.
- **`X-Vault-Namespace` header passes through** — useful for Vault
  Enterprise / OpenBao namespaces, distinct from Warden's namespaces.
- **PKI verify endpoints are unauthenticated** at the Vault level;
  Warden still requires a valid identity to reach them.
- **Returned data has Vault's normal envelope** (`{data: {data: {…}}}`
  for KV v2, etc.) — the agent decodes per Vault's API.
