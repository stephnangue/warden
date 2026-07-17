---
title: "Static Seal"
---

> `seal "static"`

A `static` seal wraps the root key with a key supplied **directly in the config**.
It auto-unseals like the KMS types, but the wrapping key lives in the file — use it
only where an external KMS is unavailable and the config itself is protected (for
example an encrypted secret mounted into the process).

```hcl
seal "static" {
  current_key_id = "v1"
  current_key    = "{{ env "WARDEN_STATIC_SEAL_KEY" }}"
}
```

Keep the key out of the file with
[environment-variable interpolation](/configuration/#environment-variables), as
above. Rotate by moving the old values to `previous_key` / `previous_key_id` and
setting a new `current_key` / `current_key_id`.

## Parameters

| Key | Default | Description |
|-----|---------|-------------|
| `current_key` | *(required)* | The current wrapping key. |
| `current_key_id` | *(required)* | Identifier for the current key. |
| `previous_key` | *(none)* | The prior wrapping key, kept for rotation. |
| `previous_key_id` | *(none)* | Identifier for the prior key. |

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — common parameters and other seal types.
