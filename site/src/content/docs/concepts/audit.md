---
title: "Audit"
---

Warden records every request and response to an **audit log** — a forensic
account of who asked for what, which [policy](/concepts/policies/) decision was made, and
which [credential](/concepts/credentials/) was issued. If a secret is ever misused, the
audit log is how you find out when, by whom, and through which mount.

The defining rule is that **secrets are never written in the clear**. Sensitive
values are replaced with a keyed hash, so the log is safe to ship to a SIEM yet
still useful for investigation.

## What Gets Recorded

Each operation produces two entries — a **request** entry when it arrives and a
**response** entry when it completes — serialized as one JSON object per line.
Between them they capture:

- **Identity** — the [token](/concepts/tokens/) ID and accessor, token type, principal
  and [role](/concepts/roles/), the granted policies, the [namespace](/concepts/namespaces/), and —
  when the token carries them — its verified, login-derived **metadata** attributes
  (clearance, team, on-behalf-of user), so a decision that turned on a
  [`token.metadata`](/concepts/policies/#fine-grained-access) value is explainable.
- **Request** — operation, path, HTTP method, client IP, mount point and type,
  and whether it was transparent/unauthenticated/streamed.
- **Response** — status, any warnings, the upstream URL for a proxied request,
  and — for a broker request — a description of the **credential issued**.

By default the request and response **bodies and headers are omitted** from the
log (they are noisy and often sensitive); the metadata above is what remains.

## Secrets Are Never Logged in Clear

Any value marked sensitive is run through **HMAC-SHA256** with a per-device key
and written as `hmac-sha256:<hex>` instead of the plaintext. The hash is
deterministic — the *same* input always produces the *same* hash under a given
device — so you can correlate occurrences of a value across the log without the
log ever revealing it.

By default Warden salts the **issued credential's secret data**
(`response.credential.data`) — the access keys, tokens, and passwords Warden
injects. Non-secret metadata is logged in clear: a forwarded token's subject, and
the inputs a policy `condition` referenced to decide a request
(`auth.policy_results.condition.inputs`). Those input values are descriptive by
design, but one — a clearance level, a request-body field — can still be
sensitive, so they are salt-able per key. You can extend or narrow this per device:

- **CEL condition inputs** — when a policy `condition` decides a request, the
  values it referenced are recorded under `auth.policy_results.condition.inputs`
  (path-level) so the decision is self-explanatory, keyed by the CEL path that
  was read (e.g. `token.metadata.env`, `call.args.amount`, `request.data.model`).
  These are logged in clear by default and are salt-able: `salt_fields`
  `auth.policy_results.condition.inputs` salts every input value, and
  `auth.policy_results.condition.inputs.request.data.model` salts just that one
  (the trailing segments are the dotted input key).
- `salt_fields` — additional dot-paths to HMAC, e.g. `auth.token_id` and
  `request.data.password`.
- `omit_fields` — dot-paths to drop entirely.

To check whether a known plaintext appears in the log, hash it with the same
device key via the `sys/audit-hash/<path>` endpoint and compare:

```bash
# returns hmac-sha256:... for the given input under this device's key
warden write sys/audit-hash/file input="AKIA...EXAMPLE"
```

## Audit Devices

An **audit device** is a pluggable sink that receives the formatted entries.
Warden ships the **`file`** device, which writes JSON lines to a file and rotates
them. You enable devices from the CLI, in declarative server config, or over the
`sys/audit/<path>` API, and a device's salt is **not preserved** across
disable/enable — a re-enabled device gets a fresh key, so old hashes no longer
correlate.

For the full configuration reference, the three ways to enable a device, rotation
and retention, and troubleshooting, see the
[Audit Devices](/audit-devices/) section and the
[file device guide](/audit-devices/file/).

## Fail-Open Until Configured, Then Fail-Closed

Auditing is a hard guarantee once you opt in:

- With **no audit device registered**, Warden **fails open** — requests are
  served unaudited. This is the bootstrap state, so a fresh server can serve
  `sys/audit/...` long enough for you to enable the first device.
- Once **any device is enabled**, Warden **fails closed** — a request is served
  only if it can be audited. If every enabled device fails to write, the request
  is rejected rather than processed silently.

With several devices enabled, entries are broadcast to all of them and the
operation succeeds as long as **at least one** writes successfully. So a single
flaky sink degrades but does not block; losing *all* of them does.

> **The [dev server](/concepts/dev-server/) ships with zero audit devices** — it runs
> fail-open and unaudited, which is fine for local work and unacceptable in
> production. Enabling a device is a required step in any real deployment.

## Auditing the Broker

Two parts of the log are particular to what Warden does.

**Credential issuance.** When Warden injects a credential into a proxied request,
the response entry records *which* credential it was — its type, the source and
[spec](/concepts/credentials/) that produced it, its lease, and the token it is bound to
— with the secret itself HMAC'd. You can answer "what was handed out, from where,
to whom" without the log ever holding a usable key.

**On-behalf-of attribution.** A request can carry a [delegation](/concepts/delegation/)
chain — the subjects it is being made *for* — and the audit entry records them as `actors`,
each flagged `verified` or not. A verified actor comes from a cryptographically
attested JWT `act` claim; an unverified one from an `X-Warden-On-Behalf-Of`
header the caller self-reports. Per-request actors take precedence over
token-bound ones, so a concentrator that reuses one identity for many agents
still produces correct per-call attribution.

## Scope

Audit devices live in the **root namespace** and are **global**: every
namespace's traffic is logged to the same devices, and each entry records the
namespace it came from. Managing devices is therefore a root-namespace,
operator-level operation, not something a tenant configures.

## See Also

- [Policies](/concepts/policies/) — the authorization decisions recorded in each entry.
- [Credentials](/concepts/credentials/) — what "credential issued" in the log refers to.
- [Tokens](/concepts/tokens/) — the identity fields logged per request.
- [Namespaces](/concepts/namespaces/) — recorded per entry; devices are root-scoped.
- [Audit Devices](/audit-devices/) — setup guides for enabling and configuring a device.
- [Configuration → Audit](/configuration/audit/) — declaring devices at startup in the config file.
- [Dev Server](/concepts/dev-server/) — ships unaudited (fail-open).
