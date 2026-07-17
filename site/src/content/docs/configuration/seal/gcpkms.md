---
title: "GCP KMS Seal"
---

> `seal "gcpkms"`

Auto-unseal backed by **Google Cloud KMS**. At startup Warden asks Cloud KMS to
decrypt the stored root key, so the node opens its barrier without an operator
present.

```hcl
seal "gcpkms" {
  project    = "my-project"
  region     = "global"
  key_ring   = "warden"
  crypto_key = "warden-unseal"
}
```

When `credentials` is omitted, Warden uses Application Default Credentials (the
`GOOGLE_APPLICATION_CREDENTIALS` env var or the attached service account) — the
preferred setup on GCE or GKE.

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `project` | *(required)* | GCP project ID. |
| `region` | *(required)* | Location of the key ring (e.g. `global`, `us-east1`). |
| `key_ring` | *(required)* | Name of the KMS key ring. |
| `crypto_key` | *(required)* | Name of the crypto key within the ring. |
| `credentials` | *(ADC / GOOGLE_APPLICATION_CREDENTIALS)* | Path to a service-account credentials file. |

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — common parameters and other seal types.
