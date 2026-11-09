---
title: "RDS"
---

The RDS provider is an **access backend** that vends ready-to-use database connection strings with short-lived IAM authentication tokens. It does not proxy database traffic — workloads use the returned connection string to connect to RDS directly.

Supports PostgreSQL and MySQL on Amazon RDS and Aurora. Both use the same IAM authentication mechanism — the only difference is the endpoint hostname.

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

A running Warden server. See the [AWS provider README](/provider-backends/aws/) for quickstart instructions (download binary, start dev server, set env vars).

### 2. AWS IAM credentials

Warden signs each RDS IAM auth token itself, with the access keys of an IAM **service user** (`warden-svc`) held on the credential source. Warden rotates those keys; the tokens it hands out live 15 minutes. `rds_iam_token` has no federated form, so the source must hold keys, and the token is always signed by that user: a spec naming `role_arn` is refused. The service user therefore needs `rds-db:connect` on the database users it serves, plus the permissions to rotate its own keys:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RDSIAMAuth",
      "Effect": "Allow",
      "Action": "rds-db:connect",
      "Resource": "arn:aws:rds-db:<region>:<account-id>:dbuser:<dbi-resource-id>/*"
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

Replace `<region>`, `<account-id>`, and `<dbi-resource-id>` (from the RDS console → Configuration → Resource ID) with your values. Narrow the `dbuser` resource to the database users Warden serves (`.../app_readonly`, `.../app_readwrite`) rather than `*`.

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

Each database user name must match the `db_user` in its corresponding credential spec (Step 4). Warden controls which workload gets which user — the database controls what that user can do.

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

## Step 2: Mount and Configure the RDS Provider

```bash
warden provider enable rds
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

## Step 3: Create a Role and Grant It

Create the role that names the policy, then a virtual group that grants it to callers admitted through the JWT mount. The role does **not** need a `cred_spec_name` — the RDS provider resolves credentials through its grants (Step 5) instead. The policy comes in Step 6; until it exists, the role write warns.

```bash
warden role create db-user -json '{
  "policies": ["rds-access"],
  "provider_path": "rds/"
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

A rule with only `mount` grants the role to every token the mount admits. See [Roles](/identity/roles/) and [Groups](/identity/groups/) for every field.

> **Advanced: grant roles by your identity provider's groups**
>
> If your identity provider puts group names in a claim (e.g., Keycloak, Auth0, Azure AD), publish the claim as a fact on the JWT mount and grant one role per group:
>
> ```bash
> warden write auth/jwt/config '{
>   "facts": {
>     "groups": "groups"
>   }
> }'
>
> warden policy write db-write - <<EOF
> path "rds/access/readwrite" { capabilities = ["read"] }
> EOF
>
> warden role create db-writer -json '{
>   "policies": ["db-write"],
>   "provider_path": "rds/"
> }'
>
> warden identity group create db-writers -json '{
>   "type": "virtual",
>   "roles": ["db-writer"],
>   "rules": [
>     { "mount": ["auth/jwt/"], "groups": ["db-write"] }
>   ]
> }'
> ```
>
> A workload whose JWT carries `{"groups": ["db-write"]}` may now ask for `db-writer`, and with it reach `rds/access/readwrite`; any other workload is refused that role. See [Grant the role with a group](/auth-methods/jwt/#step-4-grant-the-role-with-a-group).
>
> This requires an identity provider that supports custom claims. Hydra (used in the quickstart) needs a [token hook](https://www.ory.sh/docs/hydra/guides/claims-at-refresh) for custom claims. Keycloak, Auth0, and Azure AD support this natively.

## Step 4: Create a Credential Source and Spec

Create an AWS credential source with the service user's access keys and automatic rotation. The rotation period controls how often Warden rotates the source IAM access keys (creates a new key, waits for propagation, activates, deletes the old key):

```bash
warden cred source create aws-prod \
  -type=aws \
  -rotation-period=24h \
  -config access_key_id=<SERVICE_USER_ACCESS_KEY_ID> \
  -config secret_access_key=<SERVICE_USER_SECRET_ACCESS_KEY> \
  -config region=us-east-1
```

> Set `-rotation-period=0` to disable rotation (not recommended for production). The IAM permissions for rotation are included in the prerequisite policy on the service user.

Create credential specs for each database user / permission level:

```bash
# Read-only spec
warden cred spec create rds-readonly \
  -source aws-prod \
  -config mint_method=rds_iam_token \
  -config db_endpoint=mydb.abc123.us-east-1.rds.amazonaws.com \
  -config db_user=app_readonly \
  -config db_engine=postgres \
  -config region=us-east-1

# Read-write spec
warden cred spec create rds-readwrite \
  -source aws-prod \
  -config mint_method=rds_iam_token \
  -config db_endpoint=mydb.abc123.us-east-1.rds.amazonaws.com \
  -config db_user=app_readwrite \
  -config db_engine=postgres \
  -config region=us-east-1
```

For Aurora, use the cluster or reader endpoint:

```bash
warden cred spec create aurora-readonly \
  -source aws-prod \
  -config mint_method=rds_iam_token \
  -config db_endpoint=mydb.cluster-ro-abc123.us-east-1.rds.amazonaws.com \
  -config db_user=app_readonly \
  -config db_engine=postgres \
  -config region=us-east-1
```

For a database in another AWS account, create a separate source holding the keys of a service user in that account: the token is signed by the source's own keys, not by an assumed role.

## Step 5: Create Grants on the Provider

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

## Step 6: Create a Policy

Control which grants each role can access:

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

## Step 7: Get a Connection String

Get a JWT from your identity provider — see [Obtaining a JWT](/auth-methods/jwt/#obtaining-a-jwt) (the local dev setup issues one from Hydra). Export it as `$JWT_TOKEN`.

Pass the JWT directly — no login step needed — and name the role with the `role` query parameter:

```bash
curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  "${WARDEN_ADDR}/v1/rds/access/readonly?role=db-user" | jq
```

An access path has no `default_role`: a request names its role with `?role=` or the `X-Warden-Role` header, or it is refused with `400`. An operator can present a service token or a ticket from `warden login` on `X-Warden-Token` instead of a JWT; Warden then skips implicit authentication and checks that token.

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
  "${WARDEN_ADDR}/v1/rds/access/readonly?role=db-user" | jq -r .connection_string)"
```

**Go:**
```go
req, _ := http.NewRequest("GET", wardenAddr+"/v1/rds/access/readonly?role=db-user", nil)
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
    f"{WARDEN_ADDR}/v1/rds/access/readonly?role=db-user",
    headers={"Authorization": f"Bearer {jwt_token}"},
).json()

conn = psycopg2.connect(resp["connection_string"])
```

**Node.js:**
```javascript
const { Client } = require('pg');
const resp = await fetch(`${WARDEN_ADDR}/v1/rds/access/readonly?role=db-user`, {
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

This means database audit logs show both the shared IAM user and which Warden workload opened the connection — without requiring per-workload database users.
