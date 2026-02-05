# AWS Credential Source & Spec Configuration

This guide covers how to configure Warden to manage AWS credentials using IAM key rotation and STS temporary credentials.

## Architecture Overview

```
                          +-----------------------------+
                          |  AWS IAM User               |
                          |  warden-cred-source-root    |
                          |                             |
                          |  Policies:                  |
                          |  - SelfManageAccessKeys     |
                          |  - AssumeRoles (devops-*,   |
                          |    internal-*)              |
                          +--------+--------------------+
                                   |
              +--------------------+--------------------+
              |                    |                     |
       IAM key rotation    sts:AssumeRole         sts:AssumeRole
       (self-management)         |                      |
              |          +-------v--------+   +---------v-----------+
              |          | devops-*       |   | internal-*          |
              |          | roles          |   | roles               |
              |          | (consumer      |   | (source driver      |
              |          |  permissions)  |   |  permissions, e.g.  |
              |          +-------+--------+   |  Secrets Manager)   |
              |                  |             +---------+-----------+
              v                  v                       v
       Warden rotates     Warden mints           Source driver
       base keys          STS creds for           uses elevated
       periodically       consumers               permissions
```

## Prerequisites

- AWS account with IAM access
- Warden server running
- AWS CLI (for initial IAM setup)

## Step 1: Create the IAM User

Create a dedicated IAM user for Warden. This user holds long-lived access keys that Warden will rotate automatically.

```bash
aws iam create-user --user-name warden-cred-source-root
aws iam create-access-key --user-name warden-cred-source-root
```

Save the `AccessKeyId` and `SecretAccessKey` from the output.

## Step 2: Attach IAM Policies

The user needs two policies:

### SelfManageAccessKeys

Allows the user to rotate its own access keys. Warden uses this during credential rotation to create new keys and delete old ones.

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

### AssumeRoles

Allows the user to assume roles that grant actual permissions. Scope the `Resource` to match your role naming conventions.

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

## Step 3: Create the Target IAM Role

Create the role that consumers will assume through Warden. The trust policy must allow the IAM user to assume it.

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

## Step 4: Create the Credential Source in Warden

The credential source tells Warden how to authenticate to AWS and where the base credentials live.

```bash
warden -n PROD/DEV cred source create my-aws-source \
  --type aws \
  --rotation-period 24h \
  --config access_key_id=AKIA... \
  --config secret_access_key=... \
  --config region=us-east-1
```

### Source Configuration Options

| Key | Required | Description |
|-----|----------|-------------|
| `access_key_id` | Yes | IAM user access key ID |
| `secret_access_key` | Yes | IAM user secret access key |
| `region` | Yes | AWS region for API calls |
### Rotation Period

The `--rotation-period` controls how often Warden rotates the base IAM access keys. Since the IAM user can only manage its own keys and assume roles (no direct resource access), longer periods are acceptable (e.g., `720h` / 30 days). For stricter environments, use shorter periods (e.g., `12h`-`24h`).

## Step 5: Create Credential Specs

A credential spec defines what temporary credentials Warden mints for consumers. Multiple specs can share the same source, each assuming a different role with different permissions and TTLs.

```bash
# Spec for developers — assumes a role with read-only access, short TTL
warden -n PROD/DEV cred spec create developer \
  --type aws_access_keys \
  --source my-aws-source \
  --config mint_method=sts_assume_role \
  --config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-readonly-role \
  --config ttl=1h \
  --min-ttl 600s \
  --max-ttl 2h

# Spec for CI/CD pipelines — assumes a role with deploy permissions
warden -n PROD/DEV cred spec create deployer \
  --type aws_access_keys \
  --source my-aws-source \
  --config mint_method=sts_assume_role \
  --config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-deploy-role \
  --config ttl=30m \
  --min-ttl 600s \
  --max-ttl 1h

# Spec for operators — assumes a role with full access, longer TTL
warden -n PROD/DEV cred spec create operator \
  --type aws_access_keys \
  --source my-aws-source \
  --config mint_method=sts_assume_role \
  --config role_arn=arn:aws:iam::<ACCOUNT_ID>:role/devops-operator-role \
  --config ttl=2h \
  --min-ttl 600s \
  --max-ttl 4h
```

Each spec points to a different `role_arn`, so the IAM user's `AssumeRoles` policy must allow assuming all of them (the `devops-*` wildcard in Step 2 covers this).

### Mint Methods

| Method | Description |
|--------|-------------|
| `sts_assume_role` | Mints temporary credentials via STS AssumeRole |
| `secrets_manager` | Fetches credentials from AWS Secrets Manager |

### sts_assume_role Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `role_arn` | Yes | ARN of the role to assume for consumers |
| `ttl` | No | Default credential TTL (default: `1h`) |
| `session_name` | No | STS session name (default: `warden-<spec_name>`) |
| `external_id` | No | External ID for the AssumeRole call |
| `policy` | No | Inline session policy to further restrict permissions |

### secrets_manager Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `secret_id` | Yes | Secret ID or ARN in Secrets Manager |
| `version_stage` | No | Version stage to retrieve (default: `AWSCURRENT`) |

Unlike `sts_assume_role`, the `secrets_manager` mint method needs the source driver itself to call AWS Secrets Manager. The base IAM user doesn't have this permission, so the **source** needs `assume_role_arn` to assume a role that does:

```bash
# Source: assume_role_arn gives the driver Secrets Manager access
warden -n PROD/DEV cred source create my-aws-source-sm \
  --type aws \
  --rotation-period 720h \
  --config access_key_id=AKIA... \
  --config secret_access_key=... \
  --config region=us-east-1 \
  --config assume_role_arn=arn:aws:iam::<ACCOUNT_ID>:role/internal-secrets-manager-access

# Spec: fetches a secret using the source's elevated permissions
warden -n PROD/DEV cred spec create db-creds \
  --type aws_access_keys \
  --source my-aws-source-sm \
  --config mint_method=secrets_manager \
  --config secret_id=prod/database/credentials
```

### TTL Bounds

- `--min-ttl`: Minimum credential TTL. Requests for shorter TTLs are clamped up.
- `--max-ttl`: Maximum credential TTL. Requests for longer TTLs are clamped down.

## Step 6: Use the Credentials

Consumers authenticate to Warden and receive temporary AWS credentials:

```bash
# Authenticate and get credentials
LOGIN_OUTPUT=$(warden -n PROD/DEV login --method=jwt --token=$JWT --role=performer)

# Extract credentials
export AWS_ACCESS_KEY_ID=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*access_key_id=\([^,]*\).*/\1/')
export AWS_SECRET_ACCESS_KEY=$(echo "$LOGIN_OUTPUT" | grep "| data" | sed 's/.*secret_access_key=\([^ |]*\).*/\1/')

# Use with AWS CLI or SDK
aws s3 ls
```

Or use the Warden AWS gateway proxy:

```bash
export AWS_ENDPOINT_URL=http://localhost:5000/v1/PROD/DEV/aws/gateway
aws s3 ls
```

## Security Model

```
IAM User (warden-cred-source-root)
  |
  |-- SelfManageAccessKeys: can only manage its OWN keys
  |-- AssumeRoles: can only assume roles matching devops-* and internal-*
  |
  +-- devops-* roles (assumed via cred specs to mint consumer creds)
  |     |-- devops-readonly-role   (read-only access)
  |     |-- devops-deploy-role     (deploy permissions)
  |     +-- devops-operator-role   (full access)
  |
  +-- internal-* roles (assumed by source driver for internal operations)
        +-- internal-secrets-manager-access (Secrets Manager access)
```

Key principles:
- **Least privilege on the IAM user**: The user can only rotate its own keys and assume specific roles. If the base keys leak, the attacker still needs to know which roles to assume.
- **Short-lived consumer credentials**: STS credentials expire automatically (controlled by TTL). No long-lived secrets are exposed to consumers.
- **Automatic key rotation**: Warden rotates the base IAM keys on the configured schedule, limiting the window of exposure for any single key pair.
- **Audit trail**: Each STS AssumeRole call is logged in CloudTrail with a distinct session name.
