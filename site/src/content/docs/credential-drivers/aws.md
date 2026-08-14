---
title: "AWS"
---

> Source `type`: `aws`

:::tip[Prefer keyless]
This driver supports a **keyless mode** — use it instead of storing a secret inline. A stored secret is attack surface; keyless holds nothing. See [Keyless (OIDC federation)](#keyless-oidc-federation).
:::

The AWS driver brokers credentials from **Amazon Web Services**. The **source** holds a long-lived IAM **access key** (`access_key_id` / `secret_access_key`) and a region; it can optionally chain into an elevated session by assuming a role. From that authenticated base, each **spec** picks a `mint_method` to produce one of several credential shapes — temporary STS session credentials, a secret pulled from Secrets Manager, or a short-lived database IAM auth token for RDS or Redshift.

Reach for this driver when workloads need scoped, time-bounded access to AWS APIs or to IAM-authenticated databases without ever handling the operator's standing IAM key. The privileged key lives only in the source config; specs carry the per-request details (which role, which secret, which database).

## Keyless (OIDC federation)

Set `auth_method = "oidc_federation"` on the source to hold **no AWS secret**: instead
of `access_key_id`/`secret_access_key`, Warden mints an
[identity assertion](/federation/oidc-issuer/) and exchanges it via
`sts:AssumeRoleWithWebIdentity` for a short-lived session. The IAM role's trust policy
federates Warden's issuer. Works for `sts_assume_role` and for keyless
`secrets_manager` reads. The spec sets `subject_token_source` (`warden_identity` or
`agent_identity`). See [Keyless credential sources](/federation/keyless-credentials/)
for the full model.

## Credential issued

- `sts_assume_role` and `secrets_manager` issue **`aws_access_keys`**.
- `rds_iam_token` and `redshift_iam_token` issue **`db_auth_token`**.

STS credentials are **dynamic** — they carry a lease and TTL — but are **not revocable**: AWS provides no way to invalidate temporary STS credentials, so they are tracked under a synthetic lease ID and simply expire. RDS and Redshift IAM tokens are also short-lived and expiry-bound (RDS tokens last ~15 minutes; Redshift honors `duration_seconds`). Secrets Manager values are **static** — no lease, no revocation. See [the lifetime model](/concepts/credentials/#lifetime-and-revocation).

## Capabilities

- **Source rotation** — **slow**: stages a newly created IAM access key alongside the old one and waits ~5 minutes (`DefaultAWSActivationDelay`, tunable via the source's `activation_delay`) so the new key propagates through AWS IAM's eventual consistency before the old key is destroyed. Only permanent IAM keys (those with an `AKIA` prefix) are rotatable. What gets rotated is the source's own IAM access key pair.

No spec verification.

## Examples

### Keyless (recommended)

The source stores no AWS secret; the IAM role's trust policy federates Warden's issuer.

```bash
warden cred source create prod-aws-keyless \
  -type=aws \
  -config=auth_method=oidc_federation \
  -config=region=us-east-1

warden cred spec create deploy-role \
  -source=prod-aws-keyless \
  -config=mint_method=sts_assume_role \
  -config=subject_token_source=warden_identity \
  -config=role_arn=arn:aws:iam::123456789012:role/DeployRole \
  -config=ttl=1h
```

### Inline secret (discouraged)

One source holds the standing IAM key; each spec below picks a `mint_method`.

```bash
warden cred source create prod-aws \
  -type=aws \
  -config=access_key_id=AKIAIOSFODNN7EXAMPLE \
  -config=secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  -config=region=us-east-1 \
  -rotation-period=720h
```

**STS AssumeRole** — temporary session credentials for a role:

```bash
warden cred spec create deploy-role \
  -source=prod-aws \
  -config=mint_method=sts_assume_role \
  -config=role_arn=arn:aws:iam::123456789012:role/DeployRole \
  -config=ttl=1h
```

**Secrets Manager** — fetch a stored secret:

```bash
warden cred spec create db-password \
  -source=prod-aws \
  -config=mint_method=secrets_manager \
  -config=secret_id=prod/db/credentials
```

**RDS IAM auth token** — a short-lived database password:

```bash
warden cred spec create rds-token \
  -source=prod-aws \
  -config=mint_method=rds_iam_token \
  -config=db_endpoint=mydb.abc123.us-east-1.rds.amazonaws.com \
  -config=db_user=app_user \
  -config=db_engine=postgres
```

**Redshift IAM auth token** — for a provisioned cluster:

```bash
warden cred spec create redshift-token \
  -source=prod-aws \
  -config=mint_method=redshift_iam_token \
  -config=db_endpoint=mycluster.abc123.us-east-1.redshift.amazonaws.com \
  -config=cluster_identifier=mycluster \
  -config=db_name=analytics
```

## Source config

Keys for `warden cred source create <name> -type=aws -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `auth_method` | No | `static` | How the source authenticates: `static` (stored IAM key) or `oidc_federation` ([keyless](/federation/keyless-credentials/), no stored secret). |
| `access_key_id` | For `static` | — | AWS IAM access key ID for the source. Omit for keyless. |
| `secret_access_key` | For `static` | — | AWS IAM secret access key (masked). Omit for keyless. |
| `region` | Yes | — | AWS region for API calls (e.g. `us-east-1`). |
| `audience` | For keyless | — | Audience minted into the `warden_identity` assertion for this source (`oidc_federation` only; default `sts.amazonaws.com`). Rejected on a `static` source. |
| `assume_role_arn` | No | — | Optional IAM role ARN to assume for elevated permissions. **Static sources only** — not supported for `oidc_federation`. |
| `session_name` | No | `warden-source-session` | Session name for AssumeRole operations (with `assume_role_arn`). |
| `session_duration` | No | `1h` | Duration for AssumeRole sessions. |
| `external_id` | No | — | Optional external ID for AssumeRole operations. |

## Specs and mint methods

| `mint_method` | Issues | Notable spec config |
|---------------|--------|---------------------|
| `sts_assume_role` | `aws_access_keys` | `role_arn` (required), `ttl` (default `1h`), `session_name`, `external_id`, `policy` |
| `secrets_manager` | `aws_access_keys` | `secret_id` (required), `version_stage`, `version_id`, `json_key_map` |
| `rds_iam_token` | `db_auth_token` | `db_endpoint` (required), `db_user` (required), `db_engine` (default `postgres`), `db_port`, `region` |
| `redshift_iam_token` | `db_auth_token` | `db_endpoint` (required), plus exactly one of `cluster_identifier` or `workgroup_name`, `db_name`, `db_port` (default `5439`), `duration_seconds` (900–3600, default `900`), `region` |

Spec-config keys set with `warden cred spec create ... -config=key=value`:

| Key | Required | Default | Meaning |
|-----|----------|---------|---------|
| `mint_method` | Yes | — | Which minting path to use — one of the four values above. Must be set explicitly; there is no default. |
| `subject_token_source` | For keyless | — | On an `oidc_federation` source: the federated subject — `warden_identity` or `agent_identity`. |
| `credential_type` | No | `aws_access_keys` | Shape a Secrets Manager read vends: `aws_access_keys` or `api_key`. **Valid only with `mint_method=secrets_manager`** — rejected on any other mint method. |
| `role_arn` | Yes (`sts_assume_role`) | — | Role the session assumes. |
| `ttl` | No | `1h` | STS session lifetime; bounded by the spec's MinTTL/MaxTTL. |
| `session_name` | No | `warden-<spec>` | STS role session name. |
| `external_id` | No | — | External ID passed to AssumeRole. |
| `policy` | No | — | Inline session policy scoping the STS credentials. |
| `secret_id` | Yes (`secrets_manager`) | — | Secret name or ARN to fetch. |
| `version_stage` | No | — | Secrets Manager version stage. |
| `version_id` | No | — | Secrets Manager version ID. |
| `json_key_map` | No | — | Comma-separated `srcKey=destKey` remap of the secret's JSON keys. |
| `db_endpoint` | Yes (DB methods) | — | Database host endpoint. |
| `db_user` | Yes (`rds_iam_token`) | — | Database user the token authenticates as. |
| `db_engine` | No | `postgres` | RDS engine (drives the default port). |
| `db_port` | No | engine default / `5439` | Database port. |
| `cluster_identifier` | One of two (`redshift_iam_token`) | — | Provisioned Redshift cluster. |
| `workgroup_name` | One of two (`redshift_iam_token`) | — | Redshift Serverless workgroup. |
| `db_name` | No | — | Target database name for Redshift. |
| `duration_seconds` | No | `900` | Redshift token lifetime, 900–3600 seconds. |
| `region` | No | source `region` | Overrides the source region for the DB token. |

A `subject_token_source=warden_identity` spec also accepts the assertion-shaping keys —
`assertion_audience`, `assertion_resource`, `assertion_metadata_claims`,
`assertion_user_claims`, `assertion_algorithm` — documented on
[Assertion claims](/federation/assertion-claims/).

## See Also

- [Credentials](/concepts/credentials/) — the source, spec, and credential model.
- [AWS provider](/provider-backends/aws/) — full operator setup guide.
- [RDS](/provider-backends/rds/) and [Redshift](/provider-backends/redshift/) — database IAM auth tokens.
- [Credential drivers](/credential-drivers/) — every driver.
