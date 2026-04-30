# Redshift Provider

The Redshift provider is an **access backend** that vends ready-to-use database connection strings with short-lived IAM authentication tokens for Amazon Redshift. It does not proxy database traffic — workloads use the returned connection string to connect to Redshift directly.

Supports both deployment models:

- **Provisioned clusters** — via the [`redshift:GetClusterCredentialsWithIAM`](https://docs.aws.amazon.com/redshift/latest/APIReference/API_GetClusterCredentialsWithIAM.html) API. The returned database user is mapped 1:1 to the source IAM identity (no `IAM:` / `IAMA:` prefix).
- **Serverless workgroups** — via the [`redshift-serverless:GetCredentials`](https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_GetCredentials.html) API.

The legacy `GetClusterCredentials` API (with the `IAM:` / `IAMA:` user prefixes and `AutoCreate` flag) is intentionally not supported.

## Table of Contents

- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the Redshift Provider](#step-2-mount-and-configure-the-redshift-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create Grants on the Provider](#step-4-create-grants-on-the-provider)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Get a Connection String](#step-6-get-a-connection-string)
- [Attribution](#attribution)
- [Configuration Reference](#configuration-reference)

## How It Works

```
Workload ──GET /redshift/access/readonly──> Warden ──redshift:GetClusterCredentialsWithIAM──> AWS
                                              │
                                              ├── 1. Resolve grant → credential spec
                                              ├── 2. Call AWS API → DbUser + DbPassword + Expiration
                                              ├── 3. Build connection string with attribution
                                              └── 4. Return connection string + lease_duration
                                              │
Workload <── { "connection_string": "host=... password='<token>' ...", "lease_duration": 900 }
   │
   └── sql.Open("postgres", connStr)  ──> Redshift (IAM-authenticated, postgres wire protocol)
```

Unlike RDS IAM auth (where Warden signs tokens locally with SigV4 and never calls AWS), Redshift requires an actual API call to AWS for each access request. Tokens default to **15 minutes** (configurable up to 60 minutes via `duration_seconds`).

Redshift uses the PostgreSQL wire protocol on port **5439**, so any postgres driver (libpq, pgx, JDBC, psycopg2, node-postgres) works with the returned connection string.

## Prerequisites

### 1. Warden server

A running Warden server. See the [AWS provider README](../aws/README.md) for quickstart instructions (download binary, start dev server, set env vars).

### 2. AWS IAM credentials

Two IAM identities are recommended — a **service user** (whose access keys Warden holds and rotates) and a **database role** (with only the redshift credential-issuing permission, assumed via STS). This separation ensures the database-scoped identity cannot manage IAM keys.

**Service IAM user** (`warden-svc`) — holds access keys, can assume the database role and rotate its own keys:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeDBRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<account-id>:role/warden-redshift-connect"
    },
    {
      "Sid": "KeyRotation",
      "Effect": "Allow",
      "Action": [
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:ListAccessKeys"
      ],
      "Resource": "arn:aws:iam::<account-id>:user/warden-svc"
    }
  ]
}
```

**Database IAM role** (`warden-redshift-connect`) — scoped to Redshift credential issuing only.

For **provisioned clusters**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RedshiftIAMAuth",
      "Effect": "Allow",
      "Action": "redshift:GetClusterCredentialsWithIAM",
      "Resource": [
        "arn:aws:redshift:<region>:<account-id>:dbname:<cluster-id>/<db-name>",
        "arn:aws:redshift:<region>:<account-id>:cluster:<cluster-id>"
      ]
    }
  ]
}
```

For **Redshift Serverless**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RedshiftServerlessIAMAuth",
      "Effect": "Allow",
      "Action": "redshift-serverless:GetCredentials",
      "Resource": "arn:aws:redshift-serverless:<region>:<account-id>:workgroup/<workgroup-id>"
    }
  ]
}
```

The role's trust policy must allow the service user to assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<account-id>:user/warden-svc" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### 3. Redshift cluster or workgroup with IAM auth

**Provisioned clusters** support IAM authentication out of the box — no per-cluster toggle is needed.

**Serverless workgroups** support IAM authentication via `GetCredentials` once the workgroup is created.

### 4. Database user mapped to IAM

Because `GetClusterCredentialsWithIAM` and `GetCredentials` map the database user 1:1 to the IAM identity, you create a database user that matches the IAM identity name. Refer to the [AWS docs on IAM identity → database user mapping](https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-iam-access-control-identity-based.html) for the exact naming rules (different prefixes apply for IAM users vs IAM roles vs federated identities).

Once the user exists, grant the desired permissions on schemas/tables. Example for a read-only user matching an assumed IAM role named `warden-redshift-connect`:

```sql
CREATE USER "IAMR:warden-redshift-connect";
GRANT USAGE ON SCHEMA public TO "IAMR:warden-redshift-connect";
GRANT SELECT ON ALL TABLES IN SCHEMA public TO "IAMR:warden-redshift-connect";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "IAMR:warden-redshift-connect";
```

Warden controls which workload gets a token for which IAM identity; Redshift controls what that identity can do.

## Step 1: Configure JWT Auth and Create a Role

Set up JWT auth for workload authentication. The auth role does **not** need a `cred_spec_name` — the Redshift provider resolves credentials via path-based provider grants instead.

```bash
warden auth enable --type=jwt

warden write auth/jwt/config \
    mode=jwt \
    jwks_url=http://localhost:4444/.well-known/jwks.json \
    default_role=db-user

warden write auth/jwt/role/db-user \
    token_policies="redshift-access" \
    user_claim=sub
```

## Step 2: Mount and Configure the Redshift Provider

```bash
warden provider enable --type=redshift

warden write redshift/config \
    auto_auth_path=auth/jwt/
```

Verify:

```bash
warden provider list
warden read redshift/config
```

## Step 3: Create a Credential Source and Spec

> **Heads-up:** Unlike `rds_iam_token` (local SigV4 signing, no network call), `redshift_iam_token` actually hits the AWS API. Warden runs a smoke-test mint against AWS at credential-spec creation time, so the spec command will fail fast if the cluster/workgroup doesn't exist or the IAM principal lacks `redshift:GetClusterCredentialsWithIAM` / `redshift-serverless:GetCredentials`.

Create an AWS credential source with the service user's access keys and automatic rotation:

```bash
warden cred source create aws-prod \
  --type=aws \
  --rotation-period=24h \
  --config access_key_id=<SERVICE_USER_ACCESS_KEY_ID> \
  --config secret_access_key=<SERVICE_USER_SECRET_ACCESS_KEY> \
  --config region=us-east-1 \
  --config assume_role_arn=arn:aws:iam::123456789:role/warden-redshift-connect
```

> The `assume_role_arn` on the source is what makes Warden call AWS as the database role rather than as the service user. Without it, the service user itself needs `redshift:GetClusterCredentialsWithIAM` permission.

### Provisioned cluster spec

```bash
warden cred spec create redshift-readonly \
  --source aws-prod \
  --config mint_method=redshift_iam_token \
  --config cluster_identifier=my-redshift-cluster \
  --config db_endpoint=my-redshift-cluster.abc123.us-east-1.redshift.amazonaws.com \
  --config db_name=analytics \
  --config region=us-east-1
```

### Serverless workgroup spec

```bash
warden cred spec create redshift-serverless-readonly \
  --source aws-prod \
  --config mint_method=redshift_iam_token \
  --config workgroup_name=my-workgroup \
  --config db_endpoint=my-workgroup.123456789.us-east-1.redshift-serverless.amazonaws.com \
  --config db_name=analytics \
  --config region=us-east-1
```

### Longer token TTL

The default token TTL is 900 seconds (15 minutes). To extend it up to 3600 seconds (60 minutes):

```bash
warden cred spec create redshift-long-running \
  --source aws-prod \
  --config mint_method=redshift_iam_token \
  --config cluster_identifier=my-redshift-cluster \
  --config db_endpoint=my-redshift-cluster.abc123.us-east-1.redshift.amazonaws.com \
  --config db_name=analytics \
  --config region=us-east-1 \
  --config duration_seconds=3600
```

## Step 4: Create Grants on the Provider

Grants map access paths to credential specs and include the database name in the connection string:

```bash
warden write redshift/grants/readonly \
    credential_spec=redshift-readonly \
    db_name=analytics

warden write redshift/grants/serverless \
    credential_spec=redshift-serverless-readonly \
    db_name=analytics
```

Verify:

```bash
warden read redshift/grants/readonly
```

## Step 5: Create a Policy

```bash
warden policy write redshift-access - <<EOF
path "redshift/access/readonly" {
  capabilities = ["read"]
}
EOF
```

For broader access:

```bash
warden policy write redshift-full-access - <<EOF
path "redshift/access/*" {
  capabilities = ["read"]
}
EOF
```

## Step 6: Get a Connection String

Get a JWT from your identity provider, then call the access path:

```bash
curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  "${WARDEN_ADDR}/v1/redshift/access/readonly" | jq
```

The auth method's `default_role` determines which policies apply. To use a specific auth role, pass the `role` query parameter:

```bash
curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  "${WARDEN_ADDR}/v1/redshift/access/readonly?role=data-team" | jq
```

The grant itself is always selected by the path (`/access/<grant-name>`); `role` just overrides which auth role — and therefore which policies — Warden uses to authorize the request.

Response:

```json
{
  "connection_string": "host=my-redshift-cluster.abc123.us-east-1.redshift.amazonaws.com port=5439 dbname=analytics user=IAMR:warden-redshift-connect password='<temp-password>' sslmode=require application_name=workload-a",
  "lease_duration": 900
}
```

### Using the connection string

The connection string is ready-to-use with any postgres driver:

**psql:**
```bash
psql "$(curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  "${WARDEN_ADDR}/v1/redshift/access/readonly" | jq -r .connection_string)"
```

**Go:**
```go
req, _ := http.NewRequest("GET", wardenAddr+"/v1/redshift/access/readonly", nil)
req.Header.Set("Authorization", "Bearer "+jwtToken)

resp, _ := http.DefaultClient.Do(req)
var result map[string]interface{}
json.NewDecoder(resp.Body).Decode(&result)

db, err := sql.Open("postgres", result["connection_string"].(string))
```

**Python:**
```python
import psycopg2, requests

resp = requests.get(
    f"{WARDEN_ADDR}/v1/redshift/access/readonly",
    headers={"Authorization": f"Bearer {jwt_token}"},
).json()

conn = psycopg2.connect(resp["connection_string"])
```

## Attribution

Warden injects the requesting principal's identity into the connection string via PostgreSQL's `application_name` parameter. It surfaces in `STV_SESSIONS`, `STL_CONNECTION_LOG`, and Redshift audit logs — letting you trace which Warden workload opened each connection without giving every workload its own database user.

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `auto_auth_path` | string | — | **Required.** Auth mount path for implicit authentication (e.g., `auth/jwt/`) |

### Credential Spec Config (`redshift_iam_token` mint method)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `redshift_iam_token` |
| `db_endpoint` | string | Yes | Redshift endpoint hostname (used in the returned connection string) |
| `cluster_identifier` | string | One of two | Redshift provisioned cluster identifier. Mutually exclusive with `workgroup_name`. |
| `workgroup_name` | string | One of two | Redshift Serverless workgroup name. Mutually exclusive with `cluster_identifier`. |
| `db_name` | string | No | Database name passed to AWS for IAM scoping. If omitted, the IAM policy must allow access to all databases on the cluster/workgroup. |
| `db_port` | string | No | Defaults to `5439` |
| `region` | string | No | AWS region (defaults to source region) |
| `duration_seconds` | int | No | Token TTL in seconds, 900–3600. Default `900`. |

### Provider Grant Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential_spec` | string | Yes | Name of the credential spec to mint |
| `db_name` | string | No | Database name to include in the connection string |
| `description` | string | No | Human-readable description |

### Response Format

| Field | Type | Description |
|-------|------|-------------|
| `connection_string` | string | Ready-to-use libpq DSN for `sql.Open()` or equivalent |
| `lease_duration` | int | Token validity in seconds (900–3600 depending on `duration_seconds`) |
