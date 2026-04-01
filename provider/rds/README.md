# RDS Provider

The RDS provider is an **access backend** that vends ready-to-use database connection strings with short-lived IAM authentication tokens. It does not proxy database traffic — workloads use the returned connection string to connect to RDS directly.

Supports PostgreSQL, MySQL, and SQL Server on Amazon RDS and Aurora. Both use the same IAM authentication mechanism — the only difference is the endpoint hostname.

## Table of Contents

- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Step 1: Configure JWT Auth and Create a Role](#step-1-configure-jwt-auth-and-create-a-role)
- [Step 2: Mount and Configure the RDS Provider](#step-2-mount-and-configure-the-rds-provider)
- [Step 3: Create a Credential Source and Spec](#step-3-create-a-credential-source-and-spec)
- [Step 4: Create Grants on the Provider](#step-4-create-grants-on-the-provider)
- [Step 5: Create a Policy](#step-5-create-a-policy)
- [Step 6: Get a Connection String](#step-6-get-a-connection-string)
- [Attribution](#attribution)
- [Configuration Reference](#configuration-reference)

## How It Works

```
Workload ──GET /rds/access/readonly──> Warden ──IAM SigV4 signing──> (no network call)
                                         │
                                         ├── 1. Resolve grant → credential spec
                                         ├── 2. Mint RDS IAM auth token (local SigV4)
                                         ├── 3. Build connection string with attribution
                                         └── 4. Return connection string + lease_duration
                                         │
Workload <── { "connection_string": "host=... password=<token> ...", "lease_duration": 900 }
   │
   └── sql.Open("postgres", connStr)  ──> RDS (IAM-authenticated)
```

Unlike Vault's database secrets engine, which creates SQL users via an admin connection, the RDS provider generates IAM auth tokens — a pure identity-plane operation. No admin credentials or database connections are needed on the Warden side.

RDS IAM tokens are valid for **15 minutes** and are generated locally via SigV4 signing (no network call to AWS).

## Prerequisites

### 1. Warden server

A running Warden server. See the [Anthropic provider README](../anthropic/README.md) for quickstart instructions (download binary, start dev server, set env vars).

### 2. AWS IAM credentials

Two IAM identities are recommended — a **service user** (whose access keys Warden holds and rotates) and a **database role** (with only `rds-db:connect`, assumed via STS). This separation ensures the database-scoped identity cannot manage IAM keys.

**Service IAM user** (`warden-svc`) — holds access keys, can assume the database role and rotate its own keys:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeDBRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<account-id>:role/warden-rds-connect"
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

**Database IAM role** (`warden-rds-connect`) — scoped to RDS IAM auth only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RDSIAMAuth",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:<region>:<account-id>:dbuser:<dbi-resource-id>/*"
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

Replace `<region>`, `<account-id>`, and `<dbi-resource-id>` (from the RDS console → Configuration → Resource ID) with your values.

> **Simpler alternative:** For non-production environments, you can use a single IAM user with both `rds-db:connect` and `iam:*AccessKey` permissions, and omit `role_arn` from the credential spec. The trade-off is that the same identity that connects to the database can also manage its own keys.

### 3. RDS instance with IAM authentication enabled

Enable IAM authentication on your RDS or Aurora instance:

- **Console**: RDS → Databases → Modify → IAM DB authentication → Enable
- **CLI**: `aws rds modify-db-instance --db-instance-identifier mydb --enable-iam-database-authentication --apply-immediately`
- **Aurora**: `aws rds modify-db-cluster --db-cluster-identifier mycluster --enable-iam-database-authentication --apply-immediately`

### 4. Database user mapped to IAM

Create a database user that authenticates via IAM instead of a password:

**PostgreSQL:**
```sql
-- Read-only user
CREATE USER app_readonly WITH LOGIN;
GRANT rds_iam TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO app_readonly;

-- Read-write user
CREATE USER app_readwrite WITH LOGIN;
GRANT rds_iam TO app_readwrite;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_readwrite;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_readwrite;
```

**MySQL:**
```sql
-- Read-only user
CREATE USER 'app_readonly'@'%' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';
GRANT SELECT ON myapp.* TO 'app_readonly'@'%';

-- Read-write user
CREATE USER 'app_readwrite'@'%' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'app_readwrite'@'%';
```

**SQL Server:**
```sql
-- Read-only user (requires RDS with Kerberos/Windows auth or IAM integration)
CREATE LOGIN [app_readonly] FROM EXTERNAL PROVIDER;
CREATE USER [app_readonly] FOR LOGIN [app_readonly];
ALTER ROLE db_datareader ADD MEMBER [app_readonly];

-- Read-write user
CREATE LOGIN [app_readwrite] FROM EXTERNAL PROVIDER;
CREATE USER [app_readwrite] FOR LOGIN [app_readwrite];
ALTER ROLE db_datareader ADD MEMBER [app_readwrite];
ALTER ROLE db_datawriter ADD MEMBER [app_readwrite];
```

> **Note:** RDS for SQL Server IAM authentication requires Active Directory integration. See [AWS docs](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html) for setup.

Each database user name must match the `db_user` in its corresponding credential spec (Step 3). Warden controls which workload gets which user — the database controls what that user can do.

## Step 1: Configure JWT Auth and Create a Role

Set up JWT auth for workload authentication. The auth role does **not** need a `cred_spec_name` — the RDS provider resolves credentials via path-based provider grants instead.

```bash
warden auth enable --type=jwt

warden write auth/jwt/config \
    mode=jwt \
    jwks_url=http://localhost:4444/.well-known/jwks.json \
    default_role=db-user

warden write auth/jwt/role/db-user \
    token_policies="rds-access" \
    user_claim=sub
```

Setting `default_role=db-user` means workloads don't need to pass `?role=` — the auth method uses this role automatically during authentication.

> **Advanced: Dynamic Policy Mapping with `groups_claim`**
>
> If your identity provider includes group claims in JWTs (e.g., Keycloak, Auth0, Azure AD), you can map groups directly to Warden policies instead of creating multiple auth roles:
>
> ```bash
> warden write auth/jwt/config \
>     mode=jwt \
>     jwks_url=http://localhost:4444/.well-known/jwks.json \
>     default_role=db-user \
>     groups_claim=groups \
>     group_policy_prefix=group-
>
> warden write auth/jwt/role/db-user \
>     token_policies="base-access" \
>     user_claim=sub
>
> # Create policies matching group names
> warden policy write group-db-read - <<EOF
> path "rds/access/readonly" { capabilities = ["read"] }
> EOF
>
> warden policy write group-db-write - <<EOF
> path "rds/access/readwrite" { capabilities = ["read"] }
> EOF
> ```
>
> A workload with JWT `{"groups": ["db-read"]}` gets policies `["base-access", "group-db-read"]` — access to `rds/access/readonly` but not `rds/access/readwrite`. The group-to-policy mapping is automatic: each group name is prefixed with `group_policy_prefix` (default `group-`) to form the policy name.
>
> This requires an identity provider that supports custom claims. Hydra (used in the quickstart) needs a [token hook](https://www.ory.sh/docs/hydra/guides/claims-at-refresh) for custom claims. Keycloak, Auth0, and Azure AD support this natively.

## Step 2: Mount and Configure the RDS Provider

```bash
warden provider enable --type=rds
```

Workloads authenticate with their JWT directly — no explicit Warden login required:

```bash
warden write rds/config \
    auto_auth_path=auth/jwt/
```

Verify:

```bash
warden provider list
warden read rds/config
```

## Step 3: Create a Credential Source and Spec

Create an AWS credential source with the service user's access keys and automatic rotation. The rotation period controls how often Warden rotates the source IAM access keys (creates a new key, waits for propagation, activates, deletes the old key):

```bash
warden cred source create aws-prod \
  --type=aws \
  --rotation-period=24h \
  --config access_key_id=<SERVICE_USER_ACCESS_KEY_ID> \
  --config secret_access_key=<SERVICE_USER_SECRET_ACCESS_KEY> \
  --config region=us-east-1
```

> Set `--rotation-period=0` to disable rotation (not recommended for production). The IAM permissions for rotation are included in the prerequisite policy on the service user.

Create credential specs for each database user / permission level. The `role_arn` points to the database IAM role from the prerequisites:

```bash
# Read-only spec
warden cred spec create rds-readonly \
  --type db_auth_token \
  --source aws-prod \
  --config mint_method=rds_iam_token \
  --config db_endpoint=mydb.abc123.us-east-1.rds.amazonaws.com \
  --config db_user=app_readonly \
  --config db_engine=postgres \
  --config region=us-east-1 \
  --config role_arn=arn:aws:iam::123456789:role/warden-rds-connect

# Read-write spec
warden cred spec create rds-readwrite \
  --type db_auth_token \
  --source aws-prod \
  --config mint_method=rds_iam_token \
  --config db_endpoint=mydb.abc123.us-east-1.rds.amazonaws.com \
  --config db_user=app_readwrite \
  --config db_engine=postgres \
  --config region=us-east-1 \
  --config role_arn=arn:aws:iam::123456789:role/warden-rds-connect
```

For Aurora, use the cluster or reader endpoint:

```bash
warden cred spec create aurora-readonly \
  --type db_auth_token \
  --source aws-prod \
  --config mint_method=rds_iam_token \
  --config db_endpoint=mydb.cluster-ro-abc123.us-east-1.rds.amazonaws.com \
  --config db_user=app_readonly \
  --config db_engine=postgres \
  --config region=us-east-1
```

For cross-account access, add `role_arn`:

```bash
warden cred spec create rds-cross-account \
  --type db_auth_token \
  --source aws-prod \
  --config mint_method=rds_iam_token \
  --config db_endpoint=mydb.xyz789.eu-west-1.rds.amazonaws.com \
  --config db_user=app_readonly \
  --config db_engine=postgres \
  --config region=eu-west-1 \
  --config role_arn=arn:aws:iam::987654321:role/rds-cross-account
```

## Step 4: Create Grants on the Provider

Grants map access paths to credential specs and include the database name in the connection string:

```bash
warden write rds/grants/readonly \
    credential_spec=rds-readonly \
    db_name=myapp \
    db_engine=postgres

warden write rds/grants/readwrite \
    credential_spec=rds-readwrite \
    db_name=myapp \
    db_engine=postgres
```

Verify:

```bash
warden read rds/grants/readonly
```

## Step 5: Create a Policy

Control which grants each token can access:

```bash
warden policy write rds-access - <<EOF
path "rds/access/readonly" {
  capabilities = ["read"]
}
EOF
```

For broader access:

```bash
warden policy write rds-full-access - <<EOF
path "rds/access/*" {
  capabilities = ["read"]
}
EOF
```

## Step 6: Get a Connection String

Get a JWT from your identity provider:

```bash
export JWT_TOKEN=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-agent&client_secret=agent-secret&scope=api:read api:write" \
  | jq -r '.access_token')
```

Pass the JWT directly — no login step needed:

```bash
curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  "${WARDEN_ADDR}/v1/rds/access/readonly" | jq
```

The auth method's `default_role` determines which policies apply. To use a specific auth role, pass the `role` query parameter:

```bash
curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  "${WARDEN_ADDR}/v1/rds/access/readonly?role=data-team" | jq
```

Response:

```json
{
  "connection_string": "host=mydb.abc123.us-east-1.rds.amazonaws.com port=5432 dbname=myapp user=app_readonly password=<iam-token> sslmode=require application_name=workload-a",
  "lease_duration": 900
}
```

### Using the connection string

The connection string is ready-to-use — no assembly required:

**psql:**
```bash
psql "$(curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  "${WARDEN_ADDR}/v1/rds/access/readonly" | jq -r .connection_string)"
```

**Go:**
```go
req, _ := http.NewRequest("GET", wardenAddr+"/v1/rds/access/readonly", nil)
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
    f"{WARDEN_ADDR}/v1/rds/access/readonly",
    headers={"Authorization": f"Bearer {jwt_token}"},
).json()

conn = psycopg2.connect(resp["connection_string"])
```

**Node.js:**
```javascript
const { Client } = require('pg');
const resp = await fetch(`${WARDEN_ADDR}/v1/rds/access/readonly`, {
  headers: { 'Authorization': `Bearer ${jwtToken}` },
}).then(r => r.json());

const client = new Client({ connectionString: resp.connection_string });
await client.connect();
```

## Attribution

Warden injects the requesting principal's identity into the connection string for database audit attribution:

| Engine | Parameter | Visible In |
|--------|-----------|------------|
| PostgreSQL | `application_name=<principal>` | `pg_stat_activity`, server logs |
| MySQL | `connectionAttributes=program_name:<principal>` | `performance_schema.session_connect_attrs` |
| SQL Server | `app name=<principal>` | `sys.dm_exec_sessions` |

This means database audit logs show both the shared IAM user and which Warden workload opened the connection — without requiring per-workload database users.

## Configuration Reference

### Provider Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `auto_auth_path` | string | — | Auth mount path for implicit authentication (e.g., `auth/jwt/`) |

### Credential Spec Config (`db_auth_token` type)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mint_method` | string | Yes | Must be `rds_iam_token` |
| `db_endpoint` | string | Yes | RDS endpoint hostname |
| `db_user` | string | Yes | Database user mapped to IAM identity |
| `db_engine` | string | No | `postgres` (default), `mysql`, or `sqlserver` |
| `db_port` | string | No | Defaults based on engine (5432, 3306, 1433) |
| `region` | string | No | AWS region (defaults to source region) |
| `role_arn` | string | No | IAM role ARN for cross-account access |

### Provider Grant Config

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential_spec` | string | Yes | Name of the credential spec to mint |
| `db_name` | string | No | Database name to include in connection string |
| `db_engine` | string | No | Overrides engine from credential spec |
| `description` | string | No | Human-readable description |

### Response Format

| Field | Type | Description |
|-------|------|-------------|
| `connection_string` | string | Ready-to-use DSN for `sql.Open()` or equivalent |
| `lease_duration` | int | Token validity in seconds (900 for RDS IAM) |
