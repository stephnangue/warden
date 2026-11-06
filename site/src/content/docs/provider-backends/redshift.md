---
title: "Redshift"
---

The Redshift provider is an **access backend** that vends ready-to-use database connection strings with short-lived IAM authentication tokens for Amazon Redshift. It does not proxy database traffic — workloads use the returned connection string to connect to Redshift directly.

Supports both deployment models:

- **Provisioned clusters** — via the [`redshift:GetClusterCredentialsWithIAM`](https://docs.aws.amazon.com/redshift/latest/APIReference/API_GetClusterCredentialsWithIAM.html) API. The returned database user is mapped 1:1 to the source IAM identity (no `IAM:` / `IAMA:` prefix).
- **Serverless workgroups** — via the [`redshift-serverless:GetCredentials`](https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_GetCredentials.html) API.

The legacy `GetClusterCredentials` API (with the `IAM:` / `IAMA:` user prefixes and `AutoCreate` flag) is intentionally not supported.

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

A running Warden server. See the [AWS provider README](/provider-backends/aws/) for quickstart instructions (download binary, start dev server, set env vars).

### 2. AWS IAM credentials

Warden does not hold a database password: on each access request it calls AWS for a short-lived database credential. `redshift_iam_token` has no federated form, so the credential source holds IAM keys. Two IAM identities are recommended — a **service user** (whose access keys the source holds and Warden rotates) and a **database role** (with only the redshift credential-issuing permission, assumed via STS through the source's `assume_role_arn`). This separation ensures the database-scoped identity cannot manage IAM keys.

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

## Step 1: Configure JWT Auth

Set up JWT auth for workload authentication. Enabling the mount and configuring the key source is covered once in [JWT auth](/auth-methods/jwt/#step-1-configure-the-key-source); the commands below are for the local dev setup.

```bash
warden auth enable jwt
warden write auth/jwt/config '{
  "jwks_url": "http://localhost:4444/.well-known/jwks.json",
  "bound_issuer": "http://localhost:4444",
  "bound_audiences": ["warden"]
}'
```

## Step 2: Mount and Configure the Redshift Provider

```bash
warden provider enable redshift

warden write redshift/config \
    auto_auth_path=auth/jwt/
```

Verify:

```bash
warden provider list
warden read redshift/config
```

## Step 3: Create a Role and Grant It

Create the role that names the policy, then a virtual group that grants it to callers admitted through the JWT mount. The role does **not** need a `cred_spec_name` — the Redshift provider resolves credentials through its grants (Step 5) instead. The policy comes in Step 6; until it exists, the role write warns.

```bash
warden role create db-user -json '{
  "policies": ["redshift-access"],
  "provider_path": "redshift/"
}'

warden identity group create db-user-agents -json '{
  "type": "virtual",
  "roles": ["db-user"],
  "rules": [
    { "mount": ["auth/jwt/"] }
  ]
}'
```

:::caution[In production, register the agent]
The group above grants the role to every agent the mount admits: fine for trying the provider, not for production. In production, register each agent: create an [entity](/identity/entities/) for it, have its team [sponsor](/identity/sponsors/) it, and grant the role through a [static group](/identity/groups/) that lists the entity. Mark the role `governed_only` so no virtual group can grant it. Claim the agent's native identity last ([Rolling out](/identity/entities/#rolling-out)); [Governing an agent](/tutorials/identity/govern-an-agent/) walks through it.
:::

A rule with only `mount` grants the role to every token the mount admits. Narrow it with the token's facts, as shown in [JWT auth](/auth-methods/jwt/#step-4-grant-the-role-with-a-group). See [Roles](/identity/roles/) and [Groups](/identity/groups/) for every field.

## Step 4: Create a Credential Source and Spec

> **Heads-up:** Unlike `rds_iam_token` (local SigV4 signing, no network call), `redshift_iam_token` actually hits the AWS API. Warden runs a smoke-test mint against AWS at credential-spec creation time, so the spec command will fail fast if the cluster/workgroup doesn't exist or the IAM principal lacks `redshift:GetClusterCredentialsWithIAM` / `redshift-serverless:GetCredentials`.

Create an AWS credential source with the service user's access keys and automatic rotation:

```bash
warden cred source create aws-prod \
  -type=aws \
  -rotation-period=24h \
  -config access_key_id=<SERVICE_USER_ACCESS_KEY_ID> \
  -config secret_access_key=<SERVICE_USER_SECRET_ACCESS_KEY> \
  -config region=us-east-1 \
  -config assume_role_arn=arn:aws:iam::123456789:role/warden-redshift-connect
```

> The `assume_role_arn` on the source is what makes Warden call AWS as the database role rather than as the service user. Without it, the service user itself needs `redshift:GetClusterCredentialsWithIAM` permission.

### Provisioned cluster spec

```bash
warden cred spec create redshift-readonly \
  -source aws-prod \
  -config mint_method=redshift_iam_token \
  -config cluster_identifier=my-redshift-cluster \
  -config db_endpoint=my-redshift-cluster.abc123.us-east-1.redshift.amazonaws.com \
  -config db_name=analytics \
  -config region=us-east-1
```

### Serverless workgroup spec

```bash
warden cred spec create redshift-serverless-readonly \
  -source aws-prod \
  -config mint_method=redshift_iam_token \
  -config workgroup_name=my-workgroup \
  -config db_endpoint=my-workgroup.123456789.us-east-1.redshift-serverless.amazonaws.com \
  -config db_name=analytics \
  -config region=us-east-1
```

### Longer token TTL

The default token TTL is 900 seconds (15 minutes). To extend it up to 3600 seconds (60 minutes):

```bash
warden cred spec create redshift-long-running \
  -source aws-prod \
  -config mint_method=redshift_iam_token \
  -config cluster_identifier=my-redshift-cluster \
  -config db_endpoint=my-redshift-cluster.abc123.us-east-1.redshift.amazonaws.com \
  -config db_name=analytics \
  -config region=us-east-1 \
  -config duration_seconds=3600
```

## Step 5: Create Grants on the Provider

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

## Step 6: Create a Policy

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

## Step 7: Get a Connection String

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`, then call the access path, naming the role with the `role` query parameter:

```bash
curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  "${WARDEN_ADDR}/v1/redshift/access/readonly?role=db-user" | jq
```

The grant itself is always selected by the path (`/access/<grant-name>`); `role` selects which role — and therefore which policies — Warden uses to authorize the request. An access path has no `default_role`: a request names its role with `?role=` or the `X-Warden-Role` header, or it is refused with `400`. An operator can present a service token or a ticket from `warden login` on `X-Warden-Token` instead of a JWT; Warden then skips implicit authentication and checks that token.

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
  "${WARDEN_ADDR}/v1/redshift/access/readonly?role=db-user" | jq -r .connection_string)"
```

**Go:**
```go
req, _ := http.NewRequest("GET", wardenAddr+"/v1/redshift/access/readonly?role=db-user", nil)
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
    f"{WARDEN_ADDR}/v1/redshift/access/readonly?role=db-user",
    headers={"Authorization": f"Bearer {jwt_token}"},
).json()

conn = psycopg2.connect(resp["connection_string"])
```

## Attribution

Warden injects the requesting principal's identity into the connection string via PostgreSQL's `application_name` parameter. It surfaces in `STV_SESSIONS`, `STL_CONNECTION_LOG`, and Redshift audit logs — letting you trace which Warden workload opened each connection without giving every workload its own database user.
