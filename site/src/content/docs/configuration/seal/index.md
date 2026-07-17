---
title: "Seal"
---

> Server config stanza: `seal "<type>"`

The `seal` stanza selects the mechanism that guards the barrier's **root key** —
the master key that unlocks everything Warden persists. With no `seal` stanza the
server uses [`shamir`](/configuration/seal/shamir/), which requires operators to
supply unseal keys at startup. Declaring an **auto-unseal** seal (any of the KMS
or HSM types below) lets a node fetch and decrypt its root key from an external
service at boot with no human in the loop — configure one for any real
deployment. See [Seal and Unseal](/concepts/seal-unseal/) for the barrier model
and initialization.

```hcl
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/<id>"
}
```

## Seal types

| Type | Backing service | Auto-unseal |
|------|-----------------|-------------|
| [`shamir`](/configuration/seal/shamir/) | Shamir secret sharing (default) | no |
| [`awskms`](/configuration/seal/awskms/) | AWS KMS | yes |
| [`azurekeyvault`](/configuration/seal/azurekeyvault/) | Azure Key Vault | yes |
| [`gcpkms`](/configuration/seal/gcpkms/) | Google Cloud KMS | yes |
| [`transit`](/configuration/seal/transit/) | Vault / OpenBao Transit | yes |
| [`pkcs11`](/configuration/seal/pkcs11/) | PKCS#11 HSM | yes |
| [`ocikms`](/configuration/seal/ocikms/) | Oracle Cloud KMS | yes |
| [`kmip`](/configuration/seal/kmip/) | KMIP server | yes |
| [`static`](/configuration/seal/static/) | A static key in the config | yes |

## Common parameters

These apply to any seal type:

| Key | Default | Description |
|-----|---------|-------------|
| `disabled` | `false` | `"true"` marks this as a previous seal, kept only as a migration source when moving to a new seal. |
| `purpose` | *(none)* | Designates what the seal is used for, when more than one is specified. |

A seal migration is expressed by keeping the old stanza with `disabled = "true"`
alongside the new one.

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier, initialization, and why auto-unseal matters.
- [High Availability](/concepts/high-availability/) — why an unattended cluster needs auto-unseal.
- [Storage](/configuration/storage/) — the backend the barrier encrypts into.
