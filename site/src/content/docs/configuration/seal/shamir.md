---
title: "Shamir Seal"
---

> `seal "shamir"`

`shamir` is the **default** seal — declaring no `seal` stanza is equivalent to
`seal "shamir" {}`, and it takes no configuration of its own:

```hcl
seal "shamir" {}
```

Rather than delegate to an external service, a Shamir seal splits the root key
into shares at [initialization](/concepts/seal-unseal/#initialization); a threshold
of them must be supplied to unseal. The number of shares and the threshold are set
with `warden operator init` (`-secret-shares`, `-secret-threshold`), not in the
config file.

A Shamir seal stores no wrapping key the server can fetch for itself, so a
Shamir-sealed node does **not** unseal automatically at startup — the threshold of
shares is held by operators, off the machine, by design. For an unattended node or
[HA cluster](/concepts/high-availability/), configure an
[auto-unseal seal](/configuration/seal/) instead.

## See Also

- [Seal and Unseal](/concepts/seal-unseal/) — the barrier model and initialization.
- [Seal configuration](/configuration/seal/) — the auto-unseal alternatives.
