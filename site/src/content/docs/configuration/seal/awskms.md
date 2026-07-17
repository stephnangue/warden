---
title: "AWS KMS Seal"
---

> `seal "awskms"`

Auto-unseal backed by **AWS KMS**. At startup Warden asks KMS to decrypt the
stored root key, so the node opens its barrier without an operator present.

```hcl
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/<id>"
}
```

Credentials follow the standard AWS chain (environment, shared config, instance
role) when `access_key` / `secret_key` are omitted — the preferred setup on EC2 or
EKS.

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `kms_key_id` | *(required)* | Key ID or ARN of the KMS key. |
| `region` | *(AWS default chain)* | AWS region of the KMS key. |
| `access_key` | *(AWS default chain)* | AWS access key ID. |
| `secret_key` | *(AWS default chain)* | AWS secret access key. |
| `session_token` | *(none)* | STS session token, when using temporary credentials. |
| `endpoint` | *(AWS default)* | Custom KMS endpoint URL. |

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — common parameters and other seal types.
