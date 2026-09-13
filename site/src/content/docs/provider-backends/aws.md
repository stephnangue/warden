---
title: "AWS"
description: "Proxy the AWS SDK through Warden: the agent signs with its own identity, Warden federates it into short-lived AWS credentials for the role it asserted, and re-signs with SigV4."
---

The AWS provider puts Warden in the middle of ordinary AWS SDK traffic. The agent embeds
its identity (a JWT or a TLS client certificate) where the SDK expects credentials, and
Warden authenticates it, verifies the incoming SigV4 signature for integrity, obtains real
short-lived AWS credentials, re-signs the request, and forwards it to the target service.

There is no explicit login step, and the agent never holds an AWS key. The AWS CLI and
every AWS SDK work unmodified — only `AWS_ENDPOINT_URL` changes.

## How a request flows

The recommended setup stores **no AWS credentials at all**. Warden mints a short-lived
identity assertion describing the agent and trades it at STS for temporary credentials.

<p align="center"><img alt="An agent signs an AWS SDK request with its own identity, Warden builds an assertion carrying the agent's claims, has an external KMS sign it, presents it to AWS STS via AssumeRoleWithWebIdentity, and re-signs the request with the temporary credentials STS returns" src="/images/warden-prov-aws-oidc-fed.png" width="860"></p>

1. The user authenticates to the agent and the agent holds an ID token.
2. The agent signs an ordinary AWS SDK request, carrying **its own** identity where the
   SDK expects an access key, and **asserts a role** as it does so. Warden authenticates
   the identity against `auto_auth_path` and verifies the SigV4 signature.
3. The asserted role selects the credential spec, and Warden builds the assertion that
   spec calls for — agent claims, scoped to one audience. It goes to an **external KMS**
   unsigned.
4. The KMS returns it signed. No signing key ever lives in Warden.
5. Warden presents the assertion to **STS** as `AssumeRoleWithWebIdentity`, against the
   spec's `role_arn`.
6. STS verifies it against the trusted issuer and returns a temporary access key, secret
   key and session token.
7. Warden re-signs the request with those credentials and forwards it to AWS.

Step 3 is why one mount serves many privilege levels: the role travels on every request,
so a different role reaches a different spec, a different assertion and a different
`role_arn` — chosen per request rather than pinned to the mount.

:::note[Steps 3–6 run only on a cache miss]
Warden caches the minted credential, so most requests skip straight from step 2 to step 7.
No assertion is built, the KMS is not called, and STS is not called — the assertion is
materialized only after a miss is confirmed, so a hit costs nothing.

The entry is keyed by namespace, the **agent's token id** and the spec name, so it is
reused only by the same token asking for the same spec. It lives for the shorter of the
credential's own lease and the agent's remaining session, and an expired entry counts as a
miss and re-mints. Concurrent misses for one key are coalesced into a single mint rather
than a stampede at STS.

Re-authenticating yields a new token id and therefore a fresh mint, which is what makes
revocation take effect.
:::

The KMS leg is optional, and **recommended in production**: with a
[`signer` stanza](/configuration/signer/) configured, Warden holds no key material at all —
the issuer's private key stays in the KMS and Warden only ever asks it to sign. Omit the
stanza and the issuer signs with a locally held key instead. The exchange at STS is
identical either way, so the diagram covers both.

See [Keyless credentials](/federation/keyless-credentials/) for the trust setup and
[Assertion claims](/federation/assertion-claims/) for what the assertion carries.

:::note[The agent is the only principal here]
The `aws` provider has no user leg — it accepts no `user_auth_path` or `user_auth_role`,
because an AWS SDK request has nowhere to carry a second credential. The agent's identity
is what reaches Warden and what the assertion describes. For an MCP-shaped AWS upstream
that *does* carry both principals, see [MCP AWS](/provider-backends/mcp_aws/).
:::

## Credential modes

| Mode | Supported | How |
|---|---|---|
| **C — keyless federation** ✅ *recommended* | Yes | `auth_method=oidc_federation`, as above. **Nothing stored.** |
| **B — stored root → short-lived mint** | Yes | `auth_method=static`; IAM keys in Warden storage, rotated automatically |
| **A — static inline** | No | AWS has no long-lived credential worth serving directly; every mode mints |
| **D — chaining** | Not as a consumer | An `aws` source cannot be fed by `secret_spec` — it takes no such key. It is a chaining **producer**: `mint_method=secret_read` serves a Secrets Manager secret to other specs |
| **E — delegated user token** | No | No user leg on this provider |

See the [AWS credential driver](/credential-drivers/aws/) for every source and spec key,
[Credential concepts](/concepts/credentials/) for the full taxonomy, and
[Credential chaining](/federation/credential-chaining/) for AWS as a producer.

### When you must store IAM keys

Federation needs an OIDC trust relationship in the AWS account. Where you cannot create
one, Warden holds IAM keys in encrypted storage and rotates them on a schedule. This costs
you an IAM user and a long-lived key pair to look after —
[Appendix: IAM setup for stored keys](#appendix-iam-setup-for-stored-keys) is that setup,
and it is the only part of the page the keyless path does not need.

<p align="center"><img alt="Warden resolves the role the agent asserted to a credential spec, reads that spec's IAM keys from encrypted storage, calls STS AssumeRole for temporary credentials, and re-signs the request with SigV4 before forwarding it to the AWS service API" src="/images/warden-prov-aws-static-sts.png" width="860"></p>

Only the middle of the flow changes. Steps 3 and 4 become a storage read instead of a
signing call — the asserted role still selects the spec, and that spec's source is whose
keys are read — and step 5 is a plain `AssumeRole` rather than
`AssumeRoleWithWebIdentity`. Steps 1, 2, 6 and 7 are unchanged, and the agent still never
sees a key. Caching is unchanged too: steps 3–6 run only on a miss, so the stored keys are
read no more often than credentials are minted.

A third option keeps the keys outside Warden without federating: hold them in
Vault/OpenBao and reach them through an `hvault` source, covered in
[Vault as the credential source](#alternative-vaultopenbao-as-credential-source) below.

## Prerequisites

- Docker and Docker Compose installed and running
- AWS account with IAM access
- AWS CLI, to create the trust relationship Warden federates into

:::note[New to Warden?]
Follow [Local dev setup](/provider-backends/local-dev-setup/) to start a local dev environment (Ory Hydra + a Warden dev server) before Step 1.
:::

On the AWS side, the keyless path needs an **IAM OIDC identity provider** pointed at
Warden's issuer, and target roles whose trust policy accepts
`sts:AssumeRoleWithWebIdentity` from it. That setup lives in
[Keyless credentials](/federation/keyless-credentials/), which covers the issuer and the
trust policy together.

There is **no IAM user and no access key** to create. If you cannot federate and must fall
back to stored keys, [Appendix: IAM setup for stored keys](#appendix-iam-setup-for-stored-keys)
has that setup instead.

## Step 1: Configure JWT Auth and Create a Role

Enable the JWT auth method and point it at your identity provider's JWKS endpoint, then create a role that binds the credential spec and policy. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source) — for the local dev setup:

```bash
warden auth enable jwt
warden write auth/jwt/config jwks_url=http://localhost:4444/.well-known/jwks.json

# Create a role
warden write auth/jwt/role/aws-user \
    token_policies="aws-access" \
    user_claim=sub \
    cred_spec_name=developer
```

## Step 2: Mount and Configure the Provider

Enable the AWS provider at a path of your choice:

```bash
warden provider enable aws
```

To mount at a custom path:

```bash
warden provider enable -path=aws-prod aws
```

Verify the provider is enabled:

```bash
warden provider list
```

Configure the provider:

```bash
warden write aws/config <<EOF
{
  "proxy_domains": ["localhost"],
  "max_body_size": 10485760,
  "timeout": "30s",
  "auto_auth_path": "auth/jwt/",
  "default_role": "aws-user"
}
EOF
```

- `auto_auth_path`: the auth backend Warden uses to validate the embedded credential (JWT or certificate).
- `default_role`: the **fallback** role, used only when a request carries no role of its own.

The role that actually applies is resolved per request, highest wins:

1. The `X-Warden-Role` header — overrides everything.
2. A role encoded in the request (URL path segment or query parameter).
3. The SigV4 access key id — for this provider, whatever the SDK sends as
   `AWS_ACCESS_KEY_ID`.
4. The mount's `default_role`.

Because an SDK always signs with *some* access key id, step 3 almost always resolves, and
`default_role` is reached only by requests that arrive without one. Setting `default_role`
does **not** pin every request to that role.

For production, set `proxy_domains` to your Warden server's domain (see [DNS Configuration](#dns-configuration)).

See [Provider configuration](/provider-backends/configuration/) for the full precedence rules and the common config fields (`proxy_domains`, `timeout`, `tls_skip_verify`, `ca_data`, and more).

Verify:

```bash
warden read aws/config
```

## Step 3: Create a Credential Source and Specs

The credential source tells Warden how to reach AWS; a spec says what to mint with it.
Start with the keyless source — it stores nothing. The
[AWS credential driver](/credential-drivers/aws/) is the reference for every source and
spec key used below.

### 3a. Keyless federation (recommended)

A keyless source holds no keys, so it takes **no `rotation_period`** — there is nothing to
rotate. `audience` defaults to `sts.amazonaws.com`, which is what STS expects unless your
OIDC provider is registered with different client IDs.

```bash
warden cred source create my-aws-source -json '{
  "type": "aws",
  "config": {
    "auth_method": "oidc_federation",
    "region": "us-east-1",
    "audience": "sts.amazonaws.com"
  }
}'
```

A spec on a keyless source **must** set `subject_token_source`, which decides whose token
AWS verifies:

| Value | What STS verifies |
|---|---|
| `warden_identity` | An assertion Warden mints and signs, describing the agent. Use this unless AWS already trusts your agent's IdP. |
| `agent_identity` | The agent's own inbound JWT, forwarded unchanged. Requires AWS to trust that issuer directly, and bypasses Warden's issuer entirely. |

```bash
warden cred spec create developer -json '{
  "source": "my-aws-source",
  "min_ttl": 600,
  "max_ttl": 7200,
  "config": {
    "mint_method": "sts_assume_role",
    "subject_token_source": "warden_identity",
    "role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/devops-readonly-role",
    "ttl": "1h"
  }
}'
```

The target role's trust policy must accept the assertion — federated `AssumeRoleWithWebIdentity`
against Warden's issuer, not the IAM-user trust shown in the Prerequisites. See
[Keyless credentials](/federation/keyless-credentials/) for the IAM OIDC provider setup.

Over `auth_method=oidc_federation`, three mint methods are available: `sts_assume_role`,
`secrets_manager` and `secret_read`. The RDS and Redshift IAM-token methods are static-only.

:::caution[A keyless source cannot fall back]
A spec on a federated source that omits `subject_token_source` is **rejected when you write
it** — Warden tests the spec on create and reports the missing key — rather than being
stored and quietly authenticating with empty credentials later. For the same reason, a
federated source rejects `rotation_period`: it holds no secret of its own to rotate.
:::

### 3b. Stored IAM keys

This path needs an IAM user and its access keys, which do not exist yet — create them
first with [Appendix: IAM setup for stored keys](#appendix-iam-setup-for-stored-keys), then
use the `AccessKeyId` and `SecretAccessKey` it produces here.

```bash
warden cred source create my-aws-static -json '{
  "type": "aws",
  "rotation_period": 86400,
  "config": {
    "auth_method": "static",
    "access_key_id": "<AccessKeyId>",
    "secret_access_key": "<SecretAccessKey>",
    "region": "us-east-1"
  }
}'
```

Warden verifies the keys before storing the source — it calls `sts:GetCallerIdentity` and
rejects the write if they are not valid, so this command needs real credentials rather than
the placeholders above.

`rotation_period` is how often Warden rotates those base IAM keys — in JSON an integer
number of seconds, where the typed flags take a duration string. Since the IAM user can
only manage its own keys and assume roles (no direct resource access), longer periods are
acceptable (`2592000`, 30 days). For stricter environments use shorter ones
(`43200`–`86400`, 12–24 hours).

Verify:

```bash
warden cred source read my-aws-static
```

A credential spec defines what temporary credentials Warden mints for consumers. Multiple specs can share the same source, each assuming a different role with different permissions and TTLs — and the role the agent asserts on a request is what picks between them.

```bash
# Spec for developers — read-only access, short TTL
warden cred spec create developer -json '{
  "source": "my-aws-static",
  "min_ttl": 600,
  "max_ttl": 7200,
  "config": {
    "mint_method": "sts_assume_role",
    "role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/devops-readonly-role",
    "ttl": "1h"
  }
}'

# Spec for CI/CD pipelines — deploy permissions
warden cred spec create deployer -json '{
  "source": "my-aws-static",
  "min_ttl": 600,
  "max_ttl": 3600,
  "config": {
    "mint_method": "sts_assume_role",
    "role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/devops-deploy-role",
    "ttl": "30m"
  }
}'

# Spec for operators — full access, longer TTL
warden cred spec create operator -json '{
  "source": "my-aws-static",
  "min_ttl": 600,
  "max_ttl": 14400,
  "config": {
    "mint_method": "sts_assume_role",
    "role_arn": "arn:aws:iam::<ACCOUNT_ID>:role/devops-operator-role",
    "ttl": "2h"
  }
}'
```

`min_ttl` and `max_ttl` are integer seconds in a JSON payload, where the typed flags take
duration strings.

Each spec points to a different `role_arn`, so the IAM user's `AssumeRoles` policy must allow assuming all of them (the `devops-*` wildcard in the [appendix's AssumeRoles policy](#assumeroles) covers this).

### What the driver can do beyond this

`sts_assume_role` is the mint method proxied SDK traffic needs, and it is the only one this
page uses. The driver has four more — `secrets_manager`, `secret_read`, `rds_iam_token` and
`redshift_iam_token` — along with endpoint overrides, session policies, `secret_id`
templating and the full spec-key reference. They are properties of the credential driver
rather than of this mount, and all live on
[the AWS credential driver page](/credential-drivers/aws/).

One of them is worth knowing about from here: `secret_read` is what makes an AWS source a
chaining **producer**, serving a Secrets Manager secret to specs on *other* mounts. Note
that its `{{user.<claim>}}` templating cannot resolve for a request arriving on an `aws`
mount, since that mount never carries a user — it becomes useful when the consumer sits on
a mount that does, such as [MCP AWS](/provider-backends/mcp_aws/).

### Alternative: Vault/OpenBao as Credential Source

A third option keeps AWS credentials out of Warden without federating: hold them in
Vault/OpenBao and point an `hvault` source at it, so Warden fetches them at request time.
Two mint methods serve this mount — `static_aws` (a stored pair read from KV v2) and
`dynamic_aws` (temporary credentials generated by Vault's AWS secrets engine).

```bash
warden cred source create aws-vault-src -json '{
  "type": "hvault",
  "rotation_period": 86400,
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "approle",
    "role_id": "<role-id>",
    "secret_id": "<secret-id>",
    "approle_mount": "approle",
    "role_name": "warden-role"
  }
}'

warden cred spec create developer -json '{
  "source": "aws-vault-src",
  "min_ttl": 600,
  "max_ttl": 7200,
  "config": {
    "mint_method": "dynamic_aws",
    "aws_mount": "aws",
    "role_name": "my-vault-aws-role",
    "ttl": "1h"
  }
}'
```

Everything about the source and both mint methods — auth methods, the KV v2 keys
`static_aws` expects, lease and revocation behaviour — belongs to the
[Vault credential driver](/credential-drivers/vault/).

## Step 4: Create a Policy

Create a policy that grants access to the AWS provider gateway. Note that this policy is intentionally coarse-grained for simplicity, but it can be made much more fine-grained to restrict access to specific paths or capabilities as needed:

```bash
warden policy write aws-access - <<EOF
path "aws/gateway*" {
  capabilities = ["read", "create", "update", "delete", "patch"]
}
EOF
```

For tighter control, add runtime conditions to protect destructive operations on specific paths. For example, restrict S3 object deletion to trusted networks during business hours while leaving read access unconditional:

```bash
warden policy write aws-prod-restricted - <<EOF
path "aws/gateway*" {
  capabilities = ["delete"]
  condition = <<-CEL
    cidrContains("10.0.0.0/8", request.client_ip) &&
    now.getHours("UTC") >= 8 && now.getHours("UTC") < 18 &&
    now.getDayOfWeek("UTC") in [1, 2, 3, 4, 5]
  CEL
}

path "aws/gateway*" {
  capabilities = ["read", "create", "update", "patch"]
}
EOF
```

The `condition` is a [CEL](https://cel.dev) expression (see [CEL conditions](/concepts/cel-conditions/)): `cidrContains` restricts by network and `now.getHours`/`now.getDayOfWeek` by time of day and weekday. It must evaluate to `true` for the rule to apply, and fails closed.

Verify:

```bash
warden policy read aws-access
```

## Step 5: Configure AWS SDK and Make Requests

With Warden there is no explicit login step. The client embeds its identity directly in the AWS SDK credentials, and Warden authenticates implicitly on every request.

### JWT Auth method

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT`.

Configure the AWS SDK to use the JWT as credentials. The auth role name goes in `AWS_ACCESS_KEY_ID`, and the JWT goes in both `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`:

```bash
export AWS_ACCESS_KEY_ID="aws-user"
export AWS_SECRET_ACCESS_KEY="$JWT"
export AWS_SESSION_TOKEN="$JWT"
export AWS_ENDPOINT_URL="http://localhost:8400/v1/aws/gateway"
```

Warden reads the auth role name from `AWS_ACCESS_KEY_ID`, so this is how one mount serves
several roles: change that variable and the next request resolves to a different role, a
different credential spec, and different AWS permissions. The mount's `default_role` is
only the fallback for requests that carry no role at all — it does not override the value
the SDK signs with. To force a specific role regardless, send the `X-Warden-Role` header,
which wins over everything.

:::caution[`X-Warden-Provider` does not work with SigV4]
The header-routed form is rejected on SigV4 traffic with a directed error, because
rewriting the request URL would invalidate the signature the client already computed. Use
the path-routed `/v1/<mount>/role/<role>/gateway/<api>` form instead. `X-Warden-Role` is
unaffected — it changes which role applies without touching the URL.
:::

Then use the AWS CLI or SDK as normal — all requests are transparently proxied through Warden:

```bash
# S3
aws s3 ls
aws s3 cp file.txt s3://my-bucket/

# EC2
aws ec2 describe-instances

# DynamoDB
aws dynamodb list-tables

# Any other AWS service
aws lambda list-functions
```

Warden detects the JWT in the `X-Amz-Security-Token` header, authenticates it against the configured auth backend, verifies the SigV4 signature for request integrity, re-signs the request with real AWS credentials, and proxies it to the target service.

### Certificate Auth method

For workloads that already have X.509 certificates (Kubernetes pods with cert-manager, VMs with machine certificates, SPIFFE X.509-SVIDs), Warden can authenticate using TLS client certificates instead of JWTs.

:::note[Prerequisite]
Certificate auth requires mTLS on the Warden listener so the client certificate can be presented during the handshake. See [Enabling mTLS on the listener](/auth-methods/cert/#enabling-mtls-on-the-listener).
:::

#### Set up cert auth and configure the provider

Replace Step 1 with cert auth setup, and update the provider's `auto_auth_path`:

```bash
# Enable cert auth
warden auth enable cert

# Configure trusted CA
warden write auth/cert/config \
    trusted_ca_pem=@/path/to/ca.pem \
    default_role=aws-user

# Create a role
warden write auth/cert/role/aws-user \
    allowed_common_names="agent-*" \
    token_policies="aws-access" \
    cred_spec_name=developer

# Update the provider to use cert auth
warden write aws/config <<EOF
{
  "proxy_domains": ["localhost"],
  "auto_auth_path": "auth/cert/",
  "default_role": "aws-user"
}
EOF
```

The `allowed_common_names` field supports glob patterns; you can also match on other certificate fields. See [Create a role](/auth-methods/cert/#step-3-create-a-role) for the full set of constraint fields.

#### Configure the AWS SDK

The client uses the auth role name as both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. No session token is needed:

```bash
export AWS_ACCESS_KEY_ID="aws-user"
export AWS_SECRET_ACCESS_KEY="aws-user"
export AWS_ENDPOINT_URL="https://localhost:8400/v1/aws/gateway"
```

The client certificate is presented during the TLS handshake (or forwarded by a load balancer). Warden extracts it, authenticates against the cert auth backend, and proxies the request.

The AWS CLI does not support presenting client certificates for mTLS. Cert auth requires an HTTP client that supports mTLS, or a load balancer in front of Warden that forwards the client certificate via the `X-SSL-Client-Cert` or `X-Forwarded-Client-Cert` header. When Warden is behind such a load balancer, the AWS CLI works as normal:

## Cleanup

To stop Warden and the identity provider:

```bash
# Stop Warden (Ctrl+C in the terminal where it's running)

# Stop and remove the identity provider containers
docker compose -f docker-compose.quickstart.yml down -v
```

Since Warden dev mode uses in-memory storage, all configuration is lost when the server stops.

## DNS Configuration

The AWS provider requires **wildcard DNS configuration** for services that use virtual-hosted style URLs, particularly:

- **S3 Control API** (ListTagsForResource, GetAccessPointPolicy, etc.)
- **S3 Access Points**
- Any service where the account ID or resource name is prepended to the hostname

### How It Works

When AWS SDKs make S3 Control API requests, they construct URLs like:

```
https://<account-id>.s3-control.<region>.amazonaws.com/...
```

When proxied through Warden, the SDK rewrites the URL to:

```
https://<account-id>.<proxy-domain>:<port>/v1/aws/gateway/...
```

For example, with `proxy_domains=["localhost"]` and account `123456789012`:

```
https://123456789012.localhost:8400/v1/aws/gateway/v20180820/tags/...
```

### Local Development

**Option 1: dnsmasq (recommended for macOS)**

```bash
brew install dnsmasq
echo "address=/localhost/127.0.0.1" >> /opt/homebrew/etc/dnsmasq.conf
sudo brew services start dnsmasq
sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/localhost
```

**Option 2: Manual /etc/hosts (one account at a time)**

```
127.0.0.1 123456789012.localhost
```

**Option 3: Wildcard DNS service**

Services like [nip.io](https://nip.io) or [sslip.io](https://sslip.io) provide wildcard DNS:

```bash
warden write aws/config proxy_domains="127.0.0.1.nip.io"
```

### Production Setup

Configure wildcard DNS records pointing to your Warden server:

```
*.warden.yourdomain.com  →  A record or CNAME to Warden server
warden.yourdomain.com    →  A record to Warden server
```

Then configure Warden:

```bash
warden write aws/config proxy_domains="warden.yourdomain.com"
```

For HTTPS, you'll need a **wildcard SSL certificate** (`*.warden.yourdomain.com`), obtainable from Let's Encrypt (free, via DNS-01 challenge), commercial CAs, or internal PKI.


## Supported AWS Services

The provider includes specialized processors for:

| Processor | Services | Notes |
|-----------|----------|-------|
| **S3** | Standard S3 operations | Virtual-hosted and path-style bucket addressing |
| **S3 Control** | Account-level S3 operations | Tagging, access points, storage lens (requires wildcard DNS) |
| **S3 Access Points** | Single-region access points | ARN-based routing |
| **Generic AWS** | All other services | EC2, Lambda, DynamoDB, SQS, SNS, IAM, CloudWatch, etc. |

## Known Limitations

### Multi-Region Access Points (MRAP) Data Plane

**MRAP data plane operations (PutObject, GetObject, etc.) cannot be proxied through Warden.** This is a fundamental limitation:

1. **SigV4A Signing**: MRAP data operations use Signature Version 4A (`AWS4-ECDSA-P256-SHA256`), which Warden does not support.
2. **SDK Endpoint Resolution**: The AWS SDK resolves MRAP ARNs to virtual-hosted style URLs and sends requests directly to AWS, bypassing `AWS_ENDPOINT_URL`.
3. **Global Routing**: MRAPs route requests to the nearest region internally.

| Operation | Supported | Notes |
|-----------|-----------|-------|
| MRAP creation/deletion (S3 Control) | Yes | Uses standard SigV4 |
| MRAP policy/tagging (S3 Control) | Yes | Uses standard SigV4 |
| MRAP data operations (PutObject, GetObject) | No | Uses SigV4A, bypasses proxy |

**Workaround**: Use the underlying regional buckets directly instead of the MRAP ARN.

### S3 Directory Buckets (Express One Zone)

**S3 Directory Buckets are not currently supported.** Directory buckets (names ending in `--<zone-id>--x-s3`) use a session-based authentication mechanism: the SDK calls `CreateSession` to obtain 5-minute scoped credentials, then signs data plane requests with those credentials using the `x-amz-s3session-token` header. Warden does not yet implement this session flow.

### S3 Table Buckets

**S3 Table Buckets are not currently supported.** S3 Tables is a separate service (`s3tables.<region>.amazonaws.com`) with its own signing name (`s3tables`). Warden does not yet have a processor for this service.

### S3 Vector Buckets

**S3 Vector Buckets are not currently supported.** S3 Vectors is a separate service (`s3vectors.<region>.api.aws`) with its own signing name (`s3vectors`). Warden does not yet have a processor for this service.

### Standard (Single-Region) Access Points

Standard S3 Access Points **are fully supported**. The AWS SDK places the Access Point ARN in the request path, and Warden correctly routes these requests.

## Troubleshooting

### "Signature does not match" errors

1. Verify DNS resolves correctly:
   ```bash
   nslookup <account-id>.<proxy-domain>
   ```
2. Check that the Host header matches what the SDK signed.
3. Ensure Warden is listening on the resolved address.
4. In JWT mode, ensure the JWT has not expired — an expired JWT will cause a signature mismatch because the SDK signs with the old token value.

### Requests fail to reach Warden

1. Wildcard DNS is not configured (see [DNS Configuration](#dns-configuration)).
2. `proxy_domains` doesn't match the endpoint URL configured in your AWS SDK.
3. Firewall rules are blocking the connection.

### Request returns 401/403

1. Check that `auto_auth_path` points to a valid, enabled auth backend (e.g., `auth/jwt/`).
2. Ensure the auth role exists and has a valid `cred_spec_name`.
3. For JWT mode: verify the JWT is valid and not expired.
4. For cert mode: verify the client certificate is signed by the trusted CA configured in the cert auth backend.

### S3 Control API returns 403

This typically means DNS is not resolving `<account-id>.<proxy-domain>` to Warden, or signature verification fails due to a host mismatch.

### Debug Logging

Enable trace-level logging to see detailed request processing:

```hcl
log_level = "trace"
```

This shows incoming request details, signature verification steps, processor selection, target URL construction, and re-signing operations.

## Appendix: IAM setup for stored keys

This is the AWS-side setup for [3b. Stored IAM keys](#3b-stored-iam-keys) — the fallback
when you cannot create an OIDC trust relationship. **The keyless path needs none of it**:
there is no IAM user, no long-lived access key, and the target roles are trusted through
the OIDC provider rather than through a user ARN.

### Create the IAM User

Create a dedicated IAM user for Warden, called the Warden root user. This user holds the long-lived access keys that Warden rotates automatically.

```bash
aws iam create-user --user-name warden-cred-source-root
aws iam create-access-key --user-name warden-cred-source-root
```

Save the `AccessKeyId` and `SecretAccessKey` from the output — they are what
[3b](#3b-stored-iam-keys) stores in the credential source.

### Attach IAM Policies

The Warden root user needs two policies:

#### SelfManageAccessKeys

Allows the root user to rotate its own access keys. Warden uses this during credential rotation to create new keys and delete old ones.

```bash
aws iam put-user-policy \
  --user-name warden-cred-source-root \
  --policy-name SelfManageAccessKeys \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:ListAccessKeys"
        ],
        "Resource": "arn:aws:iam::<ACCOUNT_ID>:user/warden-cred-source-root"
      }
    ]
  }'
```

#### AssumeRoles

Allows the root user to assume roles that grant actual permissions. Scope the `Resource` to match your role naming conventions.

```bash
aws iam put-user-policy \
  --user-name warden-cred-source-root \
  --policy-name AssumeRoles \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Resource": [
          "arn:aws:iam::<ACCOUNT_ID>:role/devops-*",
          "arn:aws:iam::<ACCOUNT_ID>:role/internal-secrets-manager-access"
        ]
      }
    ]
  }'
```

### Create Target IAM Roles

Create the roles that consumers will assume through Warden. The trust policy must allow the IAM user to assume the role.

```bash
aws iam create-role \
  --role-name devops-warden-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "AWS": "arn:aws:iam::<ACCOUNT_ID>:user/warden-cred-source-root"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }'
```

Attach the permissions policies your consumers need to this role (e.g., S3 access, EC2 management).

This user-ARN trust is what differs under federation: a keyless target role trusts the OIDC
provider and conditions on the assertion's claims instead. See
[Keyless credentials](/federation/keyless-credentials/).
