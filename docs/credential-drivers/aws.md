# AWS Driver

> Source `type`: `aws`

The AWS driver brokers credentials from **Amazon Web Services**. The **source** holds a long-lived IAM **access key** (`access_key_id` / `secret_access_key`) and a region; it can optionally chain into an elevated session by assuming a role. From that authenticated base, each **spec** picks a `mint_method` to produce one of several credential shapes — temporary STS session credentials, a secret pulled from Secrets Manager, or a short-lived database IAM auth token for RDS or Redshift.

Reach for this driver when workloads need scoped, time-bounded access to AWS APIs or to IAM-authenticated databases without ever handling the operator's standing IAM key. The privileged key lives only in the source config; specs carry the per-request details (which role, which secret, which database).

## Source config

Keys for `warden cred source create <name> -type=aws -config=key=value ...`:

| Key | Required | Default | Description |
|-----|----------|---------|-------------|
| `access_key_id` | Yes | — | AWS IAM access key ID for the source. |
| `secret_access_key` | Yes | — | AWS IAM secret access key (secret, masked on read). |
| `region` | Yes | — | AWS region for API calls (e.g. `us-east-1`). |
| `assume_role_arn` | No | — | Optional IAM role ARN to assume for elevated permissions. |
| `session_name` | No | `warden-source-session` | Session name for AssumeRole operations. |
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

## Credential issued

- `sts_assume_role` and `secrets_manager` issue **`aws_access_keys`**.
- `rds_iam_token` and `redshift_iam_token` issue **`db_auth_token`**.

STS credentials are **dynamic** — they carry a lease and TTL — but are **not revocable**: AWS provides no way to invalidate temporary STS credentials, so they are tracked under a synthetic lease ID and simply expire. RDS and Redshift IAM tokens are also short-lived and expiry-bound (RDS tokens last ~15 minutes; Redshift honors `duration_seconds`). Secrets Manager values are **static** — no lease, no revocation. See [the lifetime model](../concepts/credentials.md#lifetime-and-revocation).

## Capabilities

- **Source rotation** — **slow**: stages a newly created IAM access key alongside the old one and waits ~5 minutes (`DefaultAWSActivationDelay`, tunable via the source's `activation_delay`) so the new key propagates through AWS IAM's eventual consistency before the old key is destroyed. Only permanent IAM keys (those with an `AKIA` prefix) are rotatable. What gets rotated is the source's own IAM access key pair.

No spec verification.

## Example

```bash
warden cred source create prod-aws \
  -type=aws \
  -config=access_key_id=AKIAIOSFODNN7EXAMPLE \
  -config=secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  -config=region=us-east-1 \
  -rotation-period=720h

warden cred spec create deploy-role \
  -source=prod-aws \
  -config=mint_method=sts_assume_role \
  -config=role_arn=arn:aws:iam::123456789012:role/DeployRole \
  -config=ttl=1h
```

## See Also

- [Credentials](../concepts/credentials.md) — the source, spec, and credential model.
- [AWS provider](../provider-backends/aws.md) — full operator setup guide.
- [RDS](../provider-backends/rds.md) and [Redshift](../provider-backends/redshift.md) — database IAM auth tokens.
- [Credential drivers](README.md) — every driver.
