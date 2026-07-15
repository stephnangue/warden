---
title: "Seal and Unseal"
---

Everything Warden persists is encrypted at rest behind a **barrier**. When Warden
is **sealed**, the key that decrypts that storage is not in memory — the data on
disk is unreadable, even to Warden itself. **Unsealing** is the act of
reconstructing that key in memory so the server can operate. A freshly started or
restarted Warden begins sealed and must be unsealed before it serves any request.

## The Barrier

The barrier is envelope encryption in three layers:

```
seal  ──protects──▶  root key  ──encrypts──▶  keyring  ──encrypts──▶  storage
```

- **Storage** — every value written to the backend is encrypted with the active
  data-encryption key.
- **The keyring** — the set of data-encryption keys. Rotating the keyring adds a
  new active key while keeping old keys to decrypt historical data; the keyring
  itself is encrypted by the root key.
- **The root key** — the master key that unlocks the keyring. It is never stored
  in the clear; it is protected by the **seal**.

Unsealing is therefore "obtain the root key, decrypt the keyring, and the barrier
is open." Sealing is the reverse: the root key (and keyring) are wiped from
memory, and storage goes dark again.

## Sealed vs. Unsealed

While **sealed**, the root key is absent and every barrier operation fails with
*"Warden is sealed."* No auth methods, provider mounts, or token operations work;
only a few read-only endpoints — seal status and init status — respond. While
**unsealed**, the root key lives in memory and the server operates normally.

Check the state at any time:

```bash
warden status              # exit 0 = unsealed, non-zero = sealed/uninitialized
```

backed by the `sys/seal-status` endpoint, which reports `sealed`, `initialized`,
and `ha_enabled`.

## The Seal

The **seal** is the mechanism that guards the root key. For any real deployment
Warden runs with an **auto-unseal** seal: the root key is stored encrypted by an
external **key-management service or HSM**, and at startup Warden asks that
service to decrypt it — no human in the loop. A restarted node recovers on its
own. (The [`shamir`](#the-shamir-seal) seal is the *default* when no seal stanza
is configured, but it does not auto-unseal — see below.)

The server drives this at boot in a retry loop: it repeatedly asks its configured
seal for the stored root key until the KMS responds, then opens the barrier. A
KMS that is briefly unreachable just delays unseal; the node keeps trying rather
than failing.

> **Configure an auto-unseal seal for any real deployment.** It is what lets a
> node — or a whole [HA](/concepts/high-availability/) cluster — come up without an
> operator present to feed it a key.

Supported seal types (the `type` label of the [seal stanza](#configuring-the-seal)):

| `type` | Backing service |
|--------|-----------------|
| `transit` | A Vault/OpenBao Transit mount |
| `awskms` | AWS KMS |
| `gcpkms` | Google Cloud KMS |
| `azurekeyvault` | Azure Key Vault |
| `ocikms` | Oracle Cloud KMS |
| `pkcs11` | A PKCS#11 HSM |
| `kmip` | A KMIP server |
| `static` | A static key supplied directly in the config (`current_key` / `current_key_id`, with optional `previous_*` for rotation) |
| `shamir` | Shamir secret sharing (the root key split into shares) — see below |

## Initialization

A new server is **initialized once**. Initialization generates the root key,
sets up the barrier, and issues the first [root token](/concepts/tokens/):

```bash
warden operator init
```

Useful flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `-secret-shares` | `5` | Number of shares to split the unseal key into. |
| `-secret-threshold` | `3` | Shares required to reconstruct it. |
| `-recovery-shares` | `5` | Recovery-key shares (auto-unseal mode). |
| `-recovery-threshold` | `3` | Recovery shares required. |
| `-pgp-keys` / `-recovery-pgp-keys` | — | PGP keys to encrypt each returned share. |
| `-root-token-pgp-key` | — | PGP key to encrypt the returned root token. |

With an auto-unseal seal configured, `init` returns a set of **recovery keys**
(Shamir-split, for break-glass) and the **root token**, and the server then
unseals itself from the KMS. Store the recovery keys and root token securely and
out of band — they are shown once. Encrypt them per-recipient with `-pgp-keys` /
`-root-token-pgp-key` so no single operator sees a usable key.

## The Shamir Seal

`shamir` is the **default** seal: if the configuration declares no `seal` stanza
at all, Warden uses it. It takes no configuration of its own —

```hcl
seal "shamir" {}   # equivalent to declaring no seal stanza at all
```

Rather than delegate to an external service, a Shamir seal protects the root key
with **Shamir secret sharing**: the key is split into `secret_shares` pieces, of
which `secret_threshold` are required to reconstruct it. The shares produced at
[initialization](#initialization) are handed to separate key holders so that no
one person can recover the key alone — the classic *M-of-N* custody model. The
same algorithm splits the recovery keys under an auto-unseal seal.

A Shamir seal differs from the auto-unseal seals in one operational way that
matters: it stores no wrapping key the server can fetch for itself, so a
Shamir-sealed node does **not** unseal automatically at startup the way a
KMS-, HSM-, or `static`-backed node does. The threshold of shares is held by
operators, off the machine, by design.

> **For an unattended deployment, configure an auto-unseal seal.** Auto-unseal
> (`static`, `awskms`, `transit`, and the rest) is what lets a node — or a whole
> [HA](/concepts/high-availability/) cluster — restart and open its barrier without a
> human present. Shamir keeps the key in human hands, which is its strength for
> custody and its cost for automation.

## Sealing

Sealing wipes the root key and keyring from memory; the server returns to the
sealed state and storage is unreadable until the next unseal. Warden seals itself
on shutdown and on a fatal error during unseal, so a failed startup never leaves
the barrier half-open. Re-securing a node is therefore just a restart away from a
clean sealed state.

## Configuring the Seal

The seal is declared in the server's HCL configuration with a `seal "<type>"`
stanza. For example, AWS KMS:

```hcl
seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/<id>"
}
```

Each type takes its own connection and credential keys (endpoints, key
identifiers, TLS material). A stanza can also be marked `disabled` to designate a
previous seal as a migration source when moving from one KMS to another.

## Dev Mode

The [dev server](/concepts/dev-server/) sidesteps all of this. It uses an in-memory test
seal, **auto-initializes and auto-unseals** on startup, and prints the unseal key
and root token in its banner. Everything lives in memory and is lost on restart —
which is exactly why dev mode is never for production.

## See Also

- [Storage](/concepts/storage/) — the backend the barrier encrypts.
- [High Availability](/concepts/high-availability/) — why auto-unseal matters for a cluster.
- [Tokens](/concepts/tokens/) — the root token that initialization issues.
- [Dev Server](/concepts/dev-server/) — auto-init and auto-unseal for local work.
