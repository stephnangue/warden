---
title: "PKCS#11 Seal"
---

> `seal "pkcs11"`

Auto-unseal backed by a **PKCS#11 HSM**. The root key is wrapped by a key that
never leaves the HSM.

```hcl
seal "pkcs11" {
  lib        = "/usr/lib/softhsm/libsofthsm2.so"
  slot       = "0"
  pin        = "{{ env "HSM_PIN" }}"
  key_label  = "warden-unseal"
}
```

Identify the token by `slot` or `token_label`, and the wrapping key by `key_label`
or `key_id`. Keep the PIN out of the file with
[environment-variable interpolation](/configuration/#environment-variables).

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `lib` | *(required)* | Path to the PKCS#11 shared library. |
| `pin` | *(required)* | PIN for the token. |
| `slot` | *(required)* | Slot number of the token. |
| `token_label` | *(none)* | Label of the token to use (alternative to `slot`). |
| `key_label` | *(required)* | Label of the key used to wrap the root key. |
| `key_id` | *(none)* | ID of the key (alternative to `key_label`). |
| `mechanism` | *(HSM default)* | Encryption mechanism to use. |
| `disable_software_encryption` | `false` | `true` to require the HSM to perform encryption directly. |

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — common parameters and other seal types.
