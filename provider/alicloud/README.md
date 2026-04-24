# Alibaba Cloud (Alicloud) Provider

The Alicloud provider enables proxied access to Alibaba Cloud APIs through Warden with automatic credential management and request signing. It supports two authentication modes, auto-detected per request:

- **Alicloud OpenAPI (ACS3)** — Verifies the client's `ACS3-HMAC-SHA256` signature, re-signs with real Alicloud access keys, and forwards to the target service (ECS, RAM, STS, KMS, RDS, SLB, VPC, etc.).
- **OSS Object Storage (S3-compatible)** — Verifies the client's `AWS4-HMAC-SHA256` signature, re-signs with real Alicloud OSS credentials, and forwards to `oss-{region}.aliyuncs.com`. Compatible with any S3 client running in Alicloud OSS S3-compatible mode (AWS CLI, boto3, s3cmd, MinIO, ossutil with `--s3`).

Warden is transparent to clients: they use standard Alicloud SDKs pointed at the Warden mount, and Warden injects real Alicloud credentials into every proxied request.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Provider](#step-2-mount-and-configure-the-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create a Policy](#step-4-create-a-policy)
- [Step 5: Get a JWT and Make Requests](#step-5-get-a-jwt-and-make-requests)
- [OSS Object Storage](#oss-object-storage)
- [TLS Certificate Authentication](#tls-certificate-authentication)
- [Configuration Reference](#configuration-reference)
- [Credential Reference](#credential-reference)
- [How Authentication Works](#how-authentication-works)

## Prerequisites

- An **Alicloud account** with a RAM user holding a programmatic access key. Depending on the mint method you pick in [Step 3](#step-3-create-a-credential-source-and-spec):
  - **`assume_role`** (recommended): the management key needs `AliyunSTSAssumeRoleAccess` (or an equivalent policy allowing `sts:AssumeRole`), and the target RAM role must trust the management user.
  - **Management key rotation** (optional): the management key additionally needs `ram:ListAccessKeys`, `ram:CreateAccessKey`, and `ram:DeleteAccessKey` scoped to its own RAM user. See [Management key rotation](#management-key-rotation).
  - **`static_alicloud`**: a pair of RAM access keys stored in a Vault/OpenBao KV v2 mount, with whatever Alicloud permissions your workloads need.
- Warden running (see `deploy/docker-compose.quickstart.yml` in the repository root)
- An identity provider that issues JWTs (Ory Hydra in the quickstart)

## Step 1: Configure JWT Auth and Create a Role

Set up a JWT auth method and create a role that binds the credential spec and policy. Clients authenticate directly with their JWT — no separate login step is needed.

> **This step must come before configuring the provider.** Warden validates at configuration time that the auth backend referenced by `auto_auth_path` is already mounted.

```bash
# Enable JWT auth if not already enabled
warden auth enable --type=jwt

# Configure JWT with Hydra's JWKS endpoint (from docker-compose.quickstart.yml)
warden write auth/jwt/config mode=jwt jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role that binds the credential spec and policy
warden write auth/jwt/role/alicloud-user \
    token_policies="alicloud-access" \
    user_claim=sub \
    cred_spec_name=alicloud-ops
```

## Step 2: Mount and Configure the Provider

Enable the Alicloud provider at the default path:

```bash
warden provider enable --type=alicloud
```

To mount at a custom path:

```bash
warden provider enable --type=alicloud alicloud-prod
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider with `auto_auth_path` and — if Warden is behind a reverse proxy — `proxy_domains` (see [Prerequisite: host-based routing](#prerequisite-host-based-routing)):

```bash
warden write alicloud/config <<EOF
{
  "auto_auth_path": "auth/jwt/",
  "proxy_domains": ["warden.example.com"],
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

If you're running Warden directly (no reverse proxy) and clients can resolve real Alicloud hostnames at Warden's address (e.g., via DNS or `/etc/hosts` overrides), omit `proxy_domains`.

## Step 3: Create a Credential Source and Spec

Alicloud credentials come from one of two source types. Pick the one that matches your threat model:

| Source | Mint method | Credentials returned | Use when |
|---|---|---|---|
| `alicloud` | `assume_role` | **Temporary** STS credentials (900-3600s) | Short-lived, least-privilege access (recommended) |
| `hvault` | `static_alicloud` | Permanent RAM keys from Vault KV v2 | Keys already live in your Vault/OpenBao |

The `alicloud` source requires a *management* access key that Warden uses to call the STS `AssumeRole` API per request. When keys are managed elsewhere (e.g., Vault/OpenBao), use the `hvault` source.

> **Why no `dynamic_keys`?** Alicloud RAM access keys created via `CreateAccessKey` can take seconds to minutes to propagate across regions. Minting a fresh RAM key per request would produce spurious `InvalidAccessKeyId` errors on the first use. `assume_role` issues STS session tokens that avoid that propagation window, so it's the only dynamic mint method the driver exposes.

### Option A: Alicloud source with STS `AssumeRole`

Create an `alicloud` source holding a *management* access key with permissions to call `sts:AssumeRole`. Warden calls Alicloud's STS API per request and hands clients short-lived credentials, so even a compromised session window is bounded.

The example below also enables [management key rotation](#management-key-rotation) via `--rotation-period=720h` (30 days). The `management_user_name` config key is the RAM user that owns the management key — required for rotation to work.

```bash
warden cred source create alicloud-src \
  --type=alicloud \
  --rotation-period=720h \
  --config access_key_id=LTAI-mgmt-key \
  --config access_key_secret=mgmt-secret \
  --config management_user_name=warden-management

warden cred spec create alicloud-ops \
  --source alicloud-src \
  --type=alicloud_keys \
  --config mint_method=assume_role \
  --config role_arn=acs:ram::123456789012:role/warden-ops \
  --config role_session_name=warden-session \
  --config duration_seconds=1h
```

The RAM role's trust policy must allow the management user to assume it, and the source's management key needs `AliyunSTSAssumeRoleAccess` (or an equivalent custom policy). See [Alicloud: Use STS to grant an access to a RAM role](https://www.alibabacloud.com/help/en/ram/user-guide/use-sts-tokens-to-access-resources) for setup.

Optionally pass an inline `policy` to further restrict the issued session:

```bash
warden cred spec create alicloud-readonly \
  --source alicloud-src \
  --type=alicloud_keys \
  --config mint_method=assume_role \
  --config role_arn=acs:ram::123456789012:role/warden-ops \
  --config duration_seconds=15m \
  --config 'policy={"Version":"1","Statement":[{"Effect":"Allow","Action":"ecs:Describe*","Resource":"*"}]}'
```

### Option B: Vault/OpenBao KV v2 source

When the keys already live in a Vault/OpenBao KV v2 mount, reference them without copying.

**Prerequisites:** A Vault/OpenBao instance with:
- A KV v2 mount containing your Alicloud credentials (e.g., at `secret/alicloud/prod` with `access_key_id` and `access_key_secret` fields)
- An AppRole configured for Warden access

The `hvault` source also supports rotation — it rotates its own AppRole `secret_id` (not the Alicloud keys). See the [Vault driver docs](https://github.com/stephnangue/warden/blob/main/credential/drivers/vault_driver.go) for setup.

```bash
warden cred source create alicloud-vault-src \
  --type=hvault \
  --rotation-period=24h \
  --config vault_address=https://vault.example.com \
  --config auth_method=approle \
  --config role_id=your-role-id \
  --config secret_id=your-secret-id \
  --config approle_mount=approle \
  --config role_name=warden-role

warden cred spec create alicloud-ops \
  --source alicloud-vault-src \
  --type=alicloud_keys \
  --config mint_method=static_alicloud \
  --config kv2_mount=secret \
  --config secret_path=alicloud/prod/keys
```

The KV v2 secret at `secret/alicloud/prod/keys` must contain `access_key_id` and `access_key_secret` fields.

Verify the spec:

```bash
warden cred spec read alicloud-ops
```

## Step 4: Create a Policy

Create a policy that grants access to the Alicloud provider gateway. The `+` wildcard matches a single path segment (the role name).

```bash
warden policy write alicloud-access - <<EOF
path "alicloud/role/+/gateway*" {
  capabilities = ["create", "read", "update", "delete", "patch"]
}
EOF
```

For fine-grained access control, scope capabilities to specific Alicloud hosts. For example, read-only access to ECS in `cn-hangzhou` and OSS in the same region:

```bash
warden policy write alicloud-readonly - <<EOF
path "alicloud/role/+/gateway" {
  capabilities = ["read"]
}

path "alicloud/role/+/gateway/*" {
  capabilities = ["read"]
}
EOF
```

## Step 5: Get a JWT and Make Requests

Obtain a JWT from your identity provider (client credentials flow, implicit flow, etc.), then point the Alicloud CLI at Warden.

### Prerequisite: host-based routing

Alicloud's `aliyun` CLI — and all native Alicloud SDKs (Go, Java, Python, Node.js) — treat `endpoint` as a **hostname** and build URLs as `https://<endpoint>/<action-path>`. They do **not** preserve a URL path prefix, and there is no Alicloud equivalent of AWS's `AWS_ENDPOINT_URL` env var ([SDK endpoint docs](https://github.com/aliyun/alibaba-cloud-sdk-go/blob/master/docs/11-Endpoint-EN.md)). So pointing an Alicloud client at `http://127.0.0.1:8400/v1/alicloud/role/<role>/gateway/` would skip Warden's mount path entirely — the SDK would send `POST /?Action=...` to `127.0.0.1:8400`.

> This is the key difference from Warden's AWS provider, which works out of the box with `AWS_ENDPOINT_URL` because the AWS SDK does preserve path prefixes. Alicloud's SDK doesn't, so Warden has to do the routing at the host level instead.

The clean solution is a **wildcard subdomain** plus the provider's `proxy_domains` config. Clients set their SDK endpoint to `<real-alicloud-host>.<your-proxy-domain>`, e.g.:

```
ecs.cn-hangzhou.aliyuncs.com.warden.example.com
kms.cn-beijing.aliyuncs.com.warden.example.com
oss-cn-shanghai.aliyuncs.com.warden.example.com
```

Warden recognizes the `.warden.example.com` suffix (from `proxy_domains` config), **strips it**, verifies the signature the client produced against the original subdomain host, then re-signs against the stripped Alicloud host and forwards there. The SDK stays vanilla; one wildcard DNS record + TLS cert covers every Alicloud service × region.

Example nginx config:

```nginx
server {
  listen 443 ssl;
  server_name *.warden.example.com;

  location / {
    # Prepend Warden's mount path — no role in the URL!
    # Warden picks the role from the signed access_key_id per request.
    proxy_pass http://warden-backend:8400/v1/alicloud/gateway$request_uri;
    proxy_set_header Host $http_host;
  }
}
```

- The wildcard DNS record `*.warden.example.com` maps every subdomain to the nginx/Warden address.
- `proxy_set_header Host $http_host;` preserves the full `<real>.aliyuncs.com.warden.example.com` host so Warden can match it.
- **No role in `proxy_pass`** — one nginx block serves every role. Clients carry their role in `access_key_id` (see [Client-side signing inputs](#client-side-signing-inputs-for-sdk-users)).
- **Matching provider config**: `proxy_domains: ["warden.example.com"]` (no leading dot, no trailing dot).

Warden refuses to forward to any host that isn't either (a) a direct `*.aliyuncs.com` host, or (b) `*.aliyuncs.com.<proxy_domain>`. This is the SSRF guard — metadata IPs, `localhost`, or arbitrary external hostnames all fail with `400 Bad Request`, even if the client produced a valid signature.

For local development, map a test subdomain like `ecs.cn-hangzhou.aliyuncs.com.warden.local` to `127.0.0.1` in `/etc/hosts` and configure `proxy_domains: ["warden.local"]`.

### Install and configure the Alicloud CLI

Install `aliyun-cli` ([docs](https://github.com/aliyun/aliyun-cli)):

```bash
# macOS
brew install aliyun-cli

# Linux
curl -L https://github.com/aliyun/aliyun-cli/releases/latest/download/aliyun-cli-linux-amd64.tgz | tar xz
sudo mv aliyun /usr/local/bin/
```

Create an `StsToken` profile. **`access-key-id` carries the Warden role name** (e.g. `alicloud-user`); `access-key-secret` and `sts-token` both carry the JWT:

```bash
export JWT="eyJhbGciOiJIUzI1NiJ9..."   # obtained from your IdP
export ROLE="alicloud-user"             # the auth/jwt/role/<name> you configured in Step 1

aliyun configure set \
  --profile warden \
  --mode StsToken \
  --access-key-id "${ROLE}" \
  --access-key-secret "${JWT}" \
  --sts-token "${JWT}" \
  --region cn-hangzhou
```

The CLI signs requests with ACS3-HMAC-SHA256 using `access-key-secret` and sets `x-acs-security-token` from `sts-token` — both are the JWT. `access-key-id` is part of the signed Credential field; Warden extracts it as the auth role for implicit JWT login.

### Make requests

With the wildcard subdomain setup, the endpoint for each request is the real Alicloud host with `.warden.example.com` appended:

```bash
# ECS in cn-hangzhou
aliyun --profile warden \
  --endpoint ecs.cn-hangzhou.aliyuncs.com.warden.example.com \
  ecs DescribeRegions

aliyun --profile warden \
  --endpoint ecs.cn-hangzhou.aliyuncs.com.warden.example.com \
  ecs DescribeInstances --RegionId cn-hangzhou

# RAM (global)
aliyun --profile warden \
  --endpoint ram.aliyuncs.com.warden.example.com \
  ram ListUsers

# KMS in cn-beijing
aliyun --profile warden \
  --endpoint kms.cn-beijing.aliyuncs.com.warden.example.com \
  kms ListKeys
```

The SDK signs each request with the full `<service>.<region>.aliyuncs.com.warden.example.com` host. Warden's `resolveTargetHost` strips the `.warden.example.com` suffix, verifies the client's signature against the original host, re-signs with real credentials against `ecs.cn-hangzhou.aliyuncs.com` (etc.), and forwards there.

For each request, Warden extracts the JWT from `x-acs-security-token` (it starts with `eyJ`), authenticates against `auto_auth_path`, fetches real Alicloud credentials, verifies the incoming ACS3 signature, strips the JWT, re-signs with the real credentials, and forwards to the actual Alicloud service (`ecs.cn-hangzhou.aliyuncs.com`, `ram.aliyuncs.com`, etc.).

### Client-side signing inputs (for SDK users)

In **both** JWT and cert flows, `access_key_id` carries the **role name**. Warden extracts it from the signed ACS3 `Credential` field and uses it as the auth role for implicit login. This is what lets a single nginx/Warden mount serve multiple roles transparently.

| Field | JWT auth | Cert auth |
|---|---|---|
| `access_key_id` | role name (e.g. `readonly`) | role name (e.g. `readonly`) |
| `access_key_secret` | the JWT | role name (same as `access_key_id`) |
| `x-acs-security-token` | the JWT | *omit* |
| `endpoint` | `<real>.aliyuncs.com.warden.example.com` | same |

For JWT auth, the JWT must have claims that match the declared role's `bound_claims` — otherwise auth fails. The client *declares* which role it wants via `access_key_id`; Warden *validates* the claim against the JWT before issuing credentials.

### Role resolution

Warden resolves the role in this order, first match wins:
1. URL path segment `/role/<name>/gateway/...` (explicit, used when clients aren't going through the reverse proxy)
2. `access_key_id` from the signed ACS3 `Credential` — via `GetAuthRoleFromRequest` (this is how the wildcard-subdomain setup works)
3. `default_role` from provider config (fallback)

Because of #2, the nginx `proxy_pass` does **not** need to hard-code a role. Serve everything at `/v1/alicloud/gateway/...` and let clients declare their role through the signed request.

## OSS Object Storage

OSS goes through the same wildcard subdomain as the OpenAPI path, and follows the same signing-inputs convention: **`aws_access_key_id` is the Warden role name**, not a placeholder. Warden extracts it from the signed SigV4 `Credential` field and uses it as the auth role.

```bash
export JWT="eyJhbGciOiJIUzI1NiJ9..."
export ROLE="alicloud-user"           # your auth/jwt/role/<name>

aws configure set aws_access_key_id  "${ROLE}"
aws configure set aws_secret_access_key "${JWT}"
aws configure set aws_session_token  "${JWT}"

aws s3 ls s3://my-bucket/ \
  --endpoint-url "https://oss-cn-hangzhou.aliyuncs.com.warden.example.com" \
  --region cn-hangzhou
```

Warden extracts the JWT from `X-Amz-Security-Token` (it starts with `eyJ`), authenticates against `auto_auth_path` using `${ROLE}` as the auth role (the JWT's claims must satisfy its `bound_claims`), strips the `.warden.example.com` suffix to get `oss-cn-hangzhou.aliyuncs.com`, verifies the client's SigV4 signature against the original subdomain host, and re-signs against the real OSS endpoint. Both path-style and virtual-hosted-bucket-style URLs work; the region is resolved from the SigV4 Credential scope.

## TLS Certificate Authentication

Steps 4-5 above use JWT authentication. Alternatively, you can authenticate with a TLS client certificate. This is useful for workloads that already have X.509 certificates — Kubernetes pods with cert-manager, VMs with machine certificates, or SPIFFE X.509-SVIDs from a service mesh.

> **Prerequisite:** Certificate authentication requires TLS to be enabled on the Warden listener so that client certificates can be presented during the TLS handshake (mTLS). In dev mode, use `--dev-tls` to enable TLS with auto-generated certificates. Alternatively, place Warden behind a load balancer that terminates TLS and forwards the client certificate via the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Steps 1-3 (provider setup) are identical. Replace Steps 4-5 with the following.

### Enable Cert Auth

```bash
warden auth enable --type=cert
```

### Configure Trusted CA

```bash
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=alicloud-user
```

### Create a Cert Role

```bash
warden write auth/cert/role/alicloud-user \
    allowed_common_names="agent-*" \
    token_policies="alicloud-access" \
    cred_spec_name=alicloud-ops
```

### Update Provider Config for Cert Auth

```bash
warden write alicloud/config <<EOF
{
  "auto_auth_path": "auth/cert/",
  "timeout": "30s",
  "max_body_size": 10485760
}
EOF
```

### Make Requests with Certificates

For cert-based transparent auth, the client signs with the **role name** as both `access_key_id` and `access_key_secret` (no JWT, no security token). Warden extracts the role from the ACS3 (or SigV4 for OSS) `Credential` field and matches it against the mTLS-authenticated identity.

```bash
# Alicloud OpenAPI (via any Alicloud SDK pointed at Warden over mTLS):
#   access_key_id     = "alicloud-user"
#   access_key_secret = "alicloud-user"
# The SDK will produce an ACS3-HMAC-SHA256 Authorization header with
# Credential=alicloud-user,... — Warden recognizes the role name and resolves
# the cert-authenticated identity.
```

## Configuration Reference

| Key | Type | Default | Description |
|---|---|---|---|
| `auto_auth_path` | string | — | Required. Auth mount path for implicit authentication (e.g., `auth/jwt/`, `auth/cert/`). |
| `default_role` | string | — | Fallback role when not provided in the URL path or resolved from the request. |
| `proxy_domains` | []string | `[]` | Reverse-proxy DNS suffixes. Hosts of the form `<real>.aliyuncs.com.<proxy-domain>` are rewritten to `<real>.aliyuncs.com` before forwarding. Direct `*.aliyuncs.com` hosts are always accepted; anything else is rejected (SSRF guard). Entries must not themselves contain `aliyuncs.com`. |
| `max_body_size` | int | 10MB | Maximum request body size in bytes (max 100MB). |
| `timeout` | duration | 30s | Request timeout for verification + re-sign + forwarding. |
| `tls_skip_verify` | bool | false | Skip TLS verification of upstream Alicloud endpoints (insecure; for testing only). |
| `ca_data` | string | — | Base64-encoded PEM bundle to trust as the upstream CA. |

## Credential Reference

Credential type: **`alicloud_keys`**

Data fields returned to the gateway and injected into re-signed requests:

| Field | Description | Sensitive |
|---|---|---|
| `access_key_id` | Alicloud access key ID (typically starts with `LTAI` for RAM, `STS.` for STS). | No |
| `access_key_secret` | Alicloud access key secret. | Yes |
| `security_token` | STS security token (present when `mint_method=assume_role`). | Yes |

### Source types and mint methods

| Source type | Mint method | Credentials returned | Lease behavior |
|---|---|---|---|
| `alicloud` | `assume_role` | STS temporary credentials + security token | Self-expiring (900-3600s); no server-side revocation |
| `hvault` | `static_alicloud` | Keys read from Vault KV v2 | No lease, no revocation |

The `alicloud` source supports only dynamic mint methods. When the keys already live in Vault/OpenBao, use the `hvault` source with `static_alicloud` instead.

### Alicloud source configuration

Fields on the `alicloud` source, passed as `--config key=value` to `warden cred source create`:

| Key | Default | Description |
|---|---|---|
| `access_key_id` | — | Management access key ID. Required for `assume_role`. |
| `access_key_secret` | — | Management access key secret. **Sensitive**. |
| `sts_endpoint` | `https://sts.aliyuncs.com` | STS API endpoint. Override for region-specific (`sts.<region>.aliyuncs.com`) or VPC-internal (`sts-vpc.<region>.aliyuncs.com`) access from Alibaba's private backbone. |
| `ram_endpoint` | `https://ram.aliyuncs.com` | RAM API endpoint. |
| `management_user_name` | — | RAM user that owns the management access key. Required to enable rotation. |
| `activation_delay` | `5m` | Wait between creating a rotated management key and using it (RAM eventual consistency). |
| `ca_data` | — | Base64-encoded PEM CA bundle for custom/self-signed CAs. |
| `tls_skip_verify` | false | Skip TLS verification (development only). |

In addition to `--config` fields, `warden cred source create` accepts two top-level flags that are **not** part of the driver's config map:

| Flag | Default | Description |
|---|---|---|
| `--rotation-period` | — (rotation disabled) | How often Warden rotates the source's management access key. Requires `management_user_name` to also be set. Example: `--rotation-period=720h` (30 days). See [Management key rotation](#management-key-rotation). |
| `--type` | — | Driver type. Use `--type=alicloud`. |

### Spec configuration

Fields on the `alicloud_keys` spec (passed as `--config key=value` to `warden cred spec create`):

| Key | Mint methods | Description |
|---|---|---|
| `mint_method` | all | `assume_role` (alicloud source) or `static_alicloud` (hvault source). |
| `role_arn` | `assume_role` | RAM role ARN to assume. |
| `role_session_name` | `assume_role` | STS session name (default: `warden-session`). |
| `duration_seconds` | `assume_role` | Session duration, 900-3600s (default: 3600s). |
| `policy` | `assume_role` | Optional inline policy JSON further restricting the session. |
| `kv2_mount` / `secret_path` | `static_alicloud` | KV v2 path to read keys from. |

### Management key rotation

The `alicloud` source implements Warden's `Rotatable` interface, so the management access key stored on the source can be rotated automatically without downtime. Rotation is driven by the source's `--rotation-period` flag and runs through Warden's rotation manager.

**Enable rotation** with two pieces:

- `--rotation-period` on `warden cred source create` — tells Warden's rotation manager how often to rotate (e.g., `720h` for 30 days). Without this flag the source is never rotated, even if everything else is configured.
- `--config management_user_name=<ram-user>` — the RAM user that owns the management access key. Without it, `SupportsRotation()` returns false and the rotation manager skips the source even when `--rotation-period` is set.

```bash
warden cred source create alicloud-src \
  --type=alicloud \
  --rotation-period=720h \
  --config access_key_id=LTAI-mgmt-key \
  --config access_key_secret=mgmt-secret \
  --config management_user_name=warden-management \
  --config activation_delay=5m
```

`activation_delay` is optional (defaults to 5 minutes) — the wait between minting the new key and using it, to let RAM eventual consistency propagate.

**How it works** — three-phase rotation matching the AWS driver's pattern:

1. **Prepare** — Calls `ram:ListAccessKeys` for `management_user_name` and deletes any orphaned key left from a previously failed rotation (RAM allows only 2 keys per user). Then calls `ram:CreateAccessKey` to mint a new key alongside the existing one.
2. **Wait** — Warden persists the new key and waits `activation_delay` (default 5 minutes) to let RAM eventual consistency propagate, then commits the new key into the driver's in-memory config.
3. **Cleanup** — Two-step retirement of the old key, aligning with Alibaba's [documented rotation procedure](https://www.alibabacloud.com/help/en/resource-access-management/latest/rotate-accesskey-pairs): first `ram:UpdateAccessKey` with `Status=Inactive`, then `ram:DeleteAccessKey`. Marking the key Inactive first makes any straggler client still holding the old key fail with a diagnosable `InactiveAccessKeyId` rather than a plain `NoSuchEntity`, which is what compliance audit trails look for. Guard: the driver refuses to delete the currently-active key.

If `CleanupRotation` fails, Warden's rotation manager retries with exponential backoff for up to 7 days. In-flight requests signed with the old key continue to work during the overlap window (between prepare and cleanup).

**Required RAM permissions** on the management user's policy:
- `ram:ListAccessKeys`
- `ram:CreateAccessKey`
- `ram:UpdateAccessKey`
- `ram:DeleteAccessKey`

All must be scoped to `acs:ram:*:*:user/<management_user_name>` (or equivalent). The managed policy `AliyunRAMFullAccess` is the simplest option; a custom least-privilege policy is recommended for production.

### Spec verification

When a credential spec with `mint_method=assume_role` is created or updated, the driver performs a live pre-flight check: it calls STS `AssumeRole` with `DurationSeconds=900` using the source's management keys and the spec's `role_arn`, then discards the returned session. This catches bad management keys, typo'd `role_arn` values, and missing trust-policy entries at config time rather than at first request. The call is bounded by a 10-second timeout.

## How Authentication Works

Warden sits between clients and Alicloud. Clients use standard Alicloud SDKs pointed at Warden, with their Warden-issued identity (a JWT or mTLS client certificate) woven into the signing protocol itself — not passed as a separate Bearer token.

### OpenAPI (ACS3-HMAC-SHA256)

The client signs the request with:
- `access_key_id` = any value (the role name in cert mode, or any placeholder in JWT mode)
- `access_key_secret` = the JWT (JWT mode) or the role name (cert mode)
- `x-acs-security-token` = the JWT (JWT mode only)

Warden:
1. Reads the incoming `Authorization: ACS3-HMAC-SHA256 Credential=...,SignedHeaders=...,Signature=...` header.
2. Calls `resolveTargetHost(Host, proxy_domains)` to determine the real Alicloud target. Accepts only `*.aliyuncs.com` (direct) or `*.aliyuncs.com.<proxy_domain>` (subdomain form, suffix stripped). Anything else — metadata IPs, arbitrary hostnames, typo'd proxy suffixes — is rejected up front with `400 Bad Request`.
3. Extracts the JWT from `x-acs-security-token` or the role name from the `Credential` field.
4. Performs implicit auth against `auto_auth_path` to authenticate and resolve the credential spec.
5. Verifies the incoming signature against the **original** client-signed Host (may include the proxy suffix).
6. Fetches real Alicloud keys from the credential manager.
7. Rewrites `req.Host` to the resolved target (strips the proxy suffix if present).
8. Strips `x-acs-security-token` and the original `Authorization` header.
9. Re-signs the request with `ACS3-HMAC-SHA256` against the real Alicloud host.
10. Forwards to the real Alicloud endpoint.

### OSS (AWS4-HMAC-SHA256)

Same flow, but using AWS SigV4 with the `X-Amz-Security-Token` header. Warden runs the same `resolveTargetHost` check on the incoming Host (SSRF guard), but the eventual target is derived from the region in the SigV4 credential scope: `oss-{region}.aliyuncs.com`, with virtual-hosted bucket style preserved when present.

### Why this design?

- **Clients don't know about Warden.** Standard Alicloud SDKs work unchanged — just point them at `<real-alicloud-host>.<proxy-domain>`.
- **One DNS record covers everything.** A single wildcard (`*.warden.example.com`) plus a single `proxy_domains` entry gives every Alicloud service × region coverage — no per-service routing, no path rewrites on the client, no SDK forks.
- **Host is cryptographically pinned.** The SDK signs over the full subdomain Host; Warden verifies that signature before any rewrite, so a client can't trick Warden into targeting an endpoint the client didn't intend.
- **SSRF guard at the edge.** `resolveTargetHost` rejects anything that isn't a valid Alicloud host before a single credential is touched.
- **Real Alicloud keys never leave Warden.** Clients only ever hold their JWT or certificate.
