---
name: vault
description: "Call HashiCorp Vault / OpenBao through Warden — read secrets, sign, encrypt, manage PKI — without ever holding a Vault token."
category: provider-guide
provider: vault
requires: [foundation, discovery]
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

`<mount>` and `<role>` below come from the discovery flow:
- `<mount>` is the chosen provider's path from `warden provider list`
  (e.g. `vault/`, `secrets-prod/`).
- `<role>` is the role you picked from `warden role list` to perform this
  task — it goes in the URL path.

Auth is your JWT:

```bash
URL pattern : $WARDEN_ADDR/v1/<mount>/role/<role>/gateway/<vault-api-path>
Auth header : Authorization: Bearer <JWT>     # OR X-Vault-Token: <JWT>
```

### Vault CLI

The Vault CLI works against Warden unchanged — point it at the
Warden gateway and use the JWT as the Vault token. Warden detects
the JWT prefix in `X-Vault-Token` and treats it as identity.

```bash
export VAULT_ADDR="$WARDEN_ADDR/v1/<mount>/role/<role>/gateway"
export VAULT_TOKEN="$JWT"

vault kv get secret/myapp/config
vault kv put secret/myapp/config foo=bar
vault list secret/myapp/
vault write pki/sign/server-tpl csr=@./req.csr
```

The agent never holds a real Vault token; the JWT is the identity.

### Vault SDK

For the official Go / Python / Node Vault SDKs, the same shape: set
the client's `Address` to `$WARDEN_ADDR/v1/<mount>/role/<role>/gateway`
and its `Token` to the JWT.

### Raw HTTP (curl)

```bash
curl -H "Authorization: Bearer $JWT" \
  $WARDEN_ADDR/v1/<mount>/role/<role>/gateway/v1/secret/data/myapp/config
```

## Examples

(All examples assume mount `vault/` and role `secrets-reader`;
substitute yours. `VAULT_ADDR` and `VAULT_TOKEN` are exported as
shown above.)

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
curl -H "Authorization: Bearer $JWT" \
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
