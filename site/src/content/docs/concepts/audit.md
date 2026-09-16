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
  and [role](/concepts/roles/), the granted policies, and the
  [namespace](/concepts/namespaces/). The human an agent acts for is a separate **user
  principal**, recorded as `auth.user`.
- **Why a decision went the way it did** — when a policy `condition` decided the request, the
  values it read are recorded under `auth.policy_results.condition.inputs`, keyed by CEL path.
  This is the *only* route by which a token's login-derived
  [`agent.metadata`](/concepts/policies/#fine-grained-access) reaches the log: there is no
  `auth.metadata` field, so a metadata attribute appears only if a condition referenced it.
- **Request** — operation, path, HTTP method, client IP, mount point, type and class,
  and whether it was transparent/unauthenticated/streamed.
- **Response** — status, any warnings, the upstream URL for a proxied request,
  and — for a broker request — a description of the **credential issued**.

By default the request and response **bodies and headers are omitted** from the
log (they are noisy and often sensitive); the metadata above is what remains.

### The two entries are joined by `request.id`

Every example on this page is shown expanded for reading; on disk each entry is a single
line. These two are one operation — note the shared `request.id`, and the differing `path`:

```json
{
  "type": "request",
  "timestamp": "2026-09-16T10:24:46.344756Z",
  "request": {
    "id": "host.local/F7eh2CIQpd-000002",
    "operation": "list",
    "path": "sys/policies/cbp"
  }
}
```

```json
{
  "type": "response",
  "timestamp": "2026-09-16T10:24:46.344828Z",
  "request": {
    "id": "host.local/F7eh2CIQpd-000002",
    "operation": "list",
    "path": "policies/cbp"
  },
  "response": {
    "status_code": 200
  }
}
```

:::caution[Join on `request.id`, never on `path`]
The request entry records `sys/policies/cbp`, the response entry records `policies/cbp`. The
path is normalised relative to the mount once the request reaches it, so one operation can
appear under two different paths. A query that pairs entries by path will silently mismatch.

`request.id` is stable across the pair and unique per operation. It is the only correct join
key.
:::

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
  was read (e.g. `agent.metadata.env`, `call.args.amount`, `request.data.model`).
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

## Auditing the Broker

Four parts of the log are particular to what Warden does.

**Credential issuance.** When Warden injects a credential into a proxied request,
the response entry records *which* credential it was — its type, the source and
[spec](/concepts/credentials/) that produced it, its lease, and the token it is bound to
— with the secret itself HMAC'd. You can answer "what was handed out, from where,
to whom" without the log ever holding a usable key.

**Delegation attribution.** A request can carry a [delegation](/concepts/delegation/)
chain — the subjects it is being made *for* — and the audit entry records them as `actors`.
The chain is the cryptographically-verified RFC 8693 `act` chain from the caller's token,
extracted from the signed JWT `act` claim and persisted on the token, so it survives
transparent-token caching. Because every actor is verified at source, each `actors[]`
entry is just `{subject}` — there is no `verified` field.

**User attribution.** When a request carries a [user principal](/concepts/delegation/)
— a human or another agent the agent acts for, presented by secondary transparent
authentication — both the request and response entries stamp `auth.user` with the user's
`subject`, token ID, and namespace. The mint the user scopes is thereby traceable to that
user, while the **raw user credential is never logged** — only the identity is recorded.

**MCP decisions.** For [MCP](/concepts/mcp/) traffic the entry records which rule decided the
call, under `auth.policy_results.mcp_decision`: the JSON-RPC method, the tool or resource
named, the matched rule and its type, and the policy that rule came from. Since MCP traffic
with no MCP policy in scope is denied outright, this is how you tell a deliberate refusal
from a missing policy.

## Entry Schema

### Envelope

| Field | Always present | Description |
|---|---|---|
| `type` | Yes | `request` or `response`. |
| `timestamp` | Yes | RFC 3339, UTC, sub-second precision (digits are platform-dependent). |
| `request` | Yes | The request descriptor — present on **both** entry types. |
| `response` | Response entries | Outcome of the operation. |
| `auth` | When identity was established | Omitted entirely when authentication failed. |
| `error` | On failure | The failure text. Present *without* `auth` when the token was rejected. |

### `request`

| Field | Description |
|---|---|
| `id` | Correlates the request and response entries. **The join key.** |
| `operation` | `create`, `read`, `update`, `patch`, `delete`, `list`, `help`. Streaming is the `streamed` flag, not an operation. |
| `path` | Request path. Normalised relative to the mount on the response entry — see the caution above. |
| `mount_point` | Mount prefix, e.g. `sys/`, `aws/`. |
| `mount_type` | Backend type, e.g. `system`, `aws`, `jwt`. |
| `mount_class` | `provider`, `auth`, `system`, or `audit`. Separates broker traffic from control-plane traffic. |
| `method` | HTTP method. |
| `client_ip` | Caller address. |
| `namespace_id`, `namespace_path` | The namespace the request was served in. |
| `headers`, `data` | **Omitted by default.** |
| `unauthenticated`, `streamed`, `transparent` | Present only when true. |

### `response`

| Field | Description |
|---|---|
| `status_code` | HTTP status. |
| `status_message` | Present when set. |
| `mount_class` | As above. |
| `warnings` | Non-fatal notices, e.g. unrecognised parameters. |
| `upstream_url` | For a proxied request, where it was forwarded. |
| `credential` | The credential issued — see below. |
| `auth_result` | For a login operation — see below. |
| `streamed` | Present only when true. |
| `headers`, `data` | Omitted by default. |

### `auth`

Present once an identity is established. **Absent entirely** when the token was rejected — a
request with a bad token logs `error` and no `auth`, because no identity existed to record.

| Field | Description |
|---|---|
| `token_id`, `token_accessor` | The calling token. |
| `token_type` | e.g. `warden_token`. |
| `principal_id` | The authenticated principal. |
| `role_name` | The [role](/concepts/roles/) asserted. |
| `policies` | Policies granted to the token. |
| `policy_results` | The authorization decision — see below. |
| `token_ttl`, `expires_at` | Seconds remaining; Unix expiry. |
| `namespace_id`, `namespace_path` | Token's namespace. |
| `created_by_ip` | Where the token was issued from. |
| `actors` | The verified RFC 8693 delegation chain, each entry `{subject}`. |
| `user` | The user principal — `subject`, `token_id`, `namespace_id`. |

:::note[There is no `auth.metadata`]
A token's login-derived metadata is **not** written as its own field. It reaches the log only
as a condition input — `auth.policy_results.condition.inputs["agent.metadata.team"]` — and
therefore only when a policy `condition` actually referenced it. A SIEM query on
`auth.metadata.*` matches nothing.
:::

### `auth.policy_results`

| Field | Description |
|---|---|
| `allowed` | Whether the request was permitted. |
| `granting_policies` | Which policies allowed it. |
| `condition` | The path-level CEL decision, when a condition applied. |
| `mcp_decision` | The MCP rule decision, for MCP traffic. |
| `mcp_client` | The client's **self-reported** name and version. |

**`condition`** carries `decision`, the `expression` evaluated, `error_kind` when evaluation
failed rather than returned false, `user_absent` when it referenced `user.*` with no user
present, and `inputs` — the values it read, keyed by CEL path.

**`mcp_decision`** carries `method` (empty for structural denials that bail before the method
is parsed), `name` (`params.name` for `tools/call` and `prompts/get`, `params.uri` for
`resources/read`), `decision`, `policy_name`, `matched_rule`, `rule_type`, `param_name` and
`param_value`, `batch_index` within a JSON-RPC batch, and its own per-call `condition` in the
same shape as the path-level one.

#### `mcp_decision.rule_type`

The rule family that decided. Three groups:

| Group | Values |
|---|---|
| Rule matches | `allowed_methods`, `denied_methods`, `allowed_tools`, `denied_tools`, `allowed_resources`, `denied_resources`, `allowed_prompts`, `denied_prompts` |
| CEL | `condition` (the expression returned false), `condition_error` (it failed to evaluate) |
| Structural | `header_mismatch`, `missing_body`, `malformed_jsonrpc`, `duplicate_key`, `oversized_body`, `batch_empty`, `malformed_params`, `batch_unsupported`, `batch_list_unfilterable`, `no_mcp_policy` |

Structural values outrank explicit denials when several rule-sets refuse, so a multi-policy
deny surfaces the structural reason — more useful than "tool not allowed" when the body was
unparseable in the first place.

`allowed_params`, `denied_params` and `missing_method_header` also appear in the vocabulary,
but only for reading **older records**: the policy grammar rejects those stanzas now, and argument constraints are
expressed as a CEL `condition` over `call.args`.

:::caution[`policy_name` means different things on allow and deny]
On **allow**, evaluation stops at the first rule-set that permits the call, so this names *a*
policy that allowed it — others may also have allowed it and were never consulted.

On **deny**, every rule-set refused and the most informative refusal is reported, so this
names the source of the reported *reason*, not the sole cause. Editing that one policy need
not lift the denial, because the others denied too.
:::

`mcp_client` is the client's own description of itself, taken from the request body. It is
unverified, unauthenticated and trivially forged — useful for telling one agent build from
another in a log and for nothing else. **Never gate on it.**

### `response.credential`

| Field | Description |
|---|---|
| `credential_id` | UUID for this issuance. |
| `type` | e.g. `aws_access_keys`, `vault_token`, `github_token`. |
| `category` | e.g. `cloud_iam`, `oauth`, `database`. |
| `lease_ttl`, `lease_id` | Seconds; lease for revocation tracking. `0` / absent for static credentials. |
| `token_id` | The session token the credential is bound to. |
| `source_name`, `source_type`, `spec_name` | Which [source and spec](/concepts/credentials/) produced it. |
| `revocable` | Whether Warden can revoke it. |
| `data` | The secret values — **HMAC'd by default**. |
| `metadata` | Non-secret descriptive attributes. In clear; salt-able per key. |

### `response.auth_result`

Written for login operations: `token_type`, `principal_id`, `role_name`, `policies`,
`token_ttl`, and `credential_spec` — the spec the role bound to the new token.

## Worked Examples

The first two are captured verbatim from a running server. The rest follow the schema above
and show the fields each case adds.

### A system operation

Listing policies as root. `mount_class` is `system`, marking this as control-plane rather
than broker traffic.

```json
{
  "type": "request",
  "timestamp": "2026-09-16T10:24:46.344756Z",
  "request": {
    "id": "host.local/F7eh2CIQpd-000002",
    "operation": "list",
    "path": "sys/policies/cbp",
    "mount_point": "sys/",
    "mount_type": "system",
    "mount_class": "system",
    "method": "GET",
    "client_ip": "127.0.0.1",
    "namespace_id": "root"
  },
  "auth": {
    "token_id": "wtkn_4813494d137e1631bba301d5acab6e7b",
    "token_accessor": "4K-HWR1dF-xZH4oYYw0bYIn4h2_VRjmg",
    "token_type": "warden_token",
    "principal_id": "00000000-0000-0000-0000-000000000000",
    "policies": [
      "root"
    ],
    "policy_results": {
      "allowed": true,
      "granting_policies": [
        "root"
      ]
    },
    "namespace_id": "root"
  }
}
```

### A rejected token

The token was not valid, so **no identity was established and no `auth` block is written** —
only `error`. A query looking for denials by `auth.policy_results.allowed` will not find
these; check `error` and `response.status_code` too.

```json
{
  "type": "response",
  "timestamp": "2026-09-16T10:31:58.131197Z",
  "request": {
    "id": "host.local/LnWrCQtQFN-000003",
    "operation": "list",
    "path": "sys/policies/cbp",
    "mount_point": "sys/",
    "mount_type": "system",
    "mount_class": "system",
    "method": "GET",
    "client_ip": "127.0.0.1",
    "namespace_id": "root"
  },
  "response": {
    "status_code": 403
  },
  "error": "1 error occurred:\n\t* permission denied\n\n"
}
```

### A policy denial with CEL inputs

Here identity *was* established, so `auth` is present and `policy_results.allowed` is false.
`condition.inputs` records the values the expression read, so the decision explains itself
without re-running it.

```json
{
  "type": "response",
  "timestamp": "2026-09-16T11:02:14.882301Z",
  "request": {
    "id": "host.local/Kp3nZ2wQxT-000117",
    "operation": "create",
    "path": "role/prod-agent/gateway/v1/messages",
    "mount_point": "anthropic/",
    "mount_type": "anthropic",
    "mount_class": "provider",
    "method": "POST",
    "client_ip": "10.4.2.19",
    "namespace_id": "root",
    "streamed": true
  },
  "response": {
    "status_code": 403
  },
  "auth": {
    "token_id": "wtkn_9f2c...",
    "token_type": "warden_token",
    "principal_id": "agent-7",
    "role_name": "prod-agent",
    "policies": [
      "anthropic-restricted"
    ],
    "policy_results": {
      "allowed": false,
      "condition": {
        "decision": "deny",
        "expression": "agent.metadata.env == 'prod' && request.data.model in ['claude-sonnet-4-20250514']",
        "inputs": {
          "agent.metadata.env": "staging",
          "request.data.model": "claude-opus-4-20250514"
        }
      }
    },
    "namespace_id": "root"
  },
  "error": "1 error occurred:\n\t* permission denied\n\n"
}
```

### Credential issuance

The forensic core: what was handed out, from where, bound to whom. `credential.data` is
HMAC'd, so the entry proves *which* key was injected without containing a usable one. This
request also carried a user principal, recorded under `auth.user`.

```json
{
  "type": "response",
  "timestamp": "2026-09-16T11:05:01.117420Z",
  "request": {
    "id": "host.local/Kp3nZ2wQxT-000121",
    "operation": "create",
    "path": "role/prod-agent/gateway/",
    "mount_point": "aws/",
    "mount_type": "aws",
    "mount_class": "provider",
    "method": "POST",
    "client_ip": "10.4.2.19",
    "namespace_id": "root",
    "streamed": true
  },
  "response": {
    "status_code": 200,
    "upstream_url": "https://s3.eu-west-1.amazonaws.com/",
    "credential": {
      "credential_id": "6f1d6f4e-2a77-4c1e-9a3c-0b5e6d2f1a44",
      "type": "aws_access_keys",
      "category": "cloud_iam",
      "lease_ttl": 3600,
      "lease_id": "aws/creds/prod-agent/9c1f...",
      "token_id": "wtkn_9f2c...",
      "source_name": "aws-keyless",
      "source_type": "aws",
      "spec_name": "s3-reader",
      "revocable": true,
      "data": {
        "access_key_id": "hmac-sha256:3f9c1d2e8a7b...",
        "secret_access_key": "hmac-sha256:a1b2c3d4e5f6...",
        "session_token": "hmac-sha256:9e8d7c6b5a49..."
      }
    }
  },
  "auth": {
    "token_id": "wtkn_9f2c...",
    "principal_id": "agent-7",
    "role_name": "prod-agent",
    "policies": [
      "s3-read"
    ],
    "policy_results": {
      "allowed": true,
      "granting_policies": [
        "s3-read"
      ]
    },
    "user": {
      "subject": "U012ABCDEF",
      "token_id": "wtkn_7a1b...",
      "namespace_id": "root"
    },
    "namespace_id": "root"
  }
}
```

### An MCP tool call denied by a rule

A tool matched a `denied` list. `rule_type` names the family, `matched_rule` the pattern that
hit. `mcp_client` is the caller's self-description — recorded, never trusted.

```json
{
  "type": "response",
  "timestamp": "2026-09-16T11:09:47.004918Z",
  "request": {
    "id": "host.local/Kp3nZ2wQxT-000164",
    "operation": "create",
    "path": "role/dev-agent/gateway/",
    "mount_point": "mcp/",
    "mount_type": "mcp",
    "mount_class": "provider",
    "method": "POST",
    "client_ip": "10.4.2.19",
    "namespace_id": "root",
    "streamed": true
  },
  "response": {
    "status_code": 403
  },
  "auth": {
    "token_id": "wtkn_4d8e...",
    "principal_id": "agent-3",
    "role_name": "dev-agent",
    "policies": [
      "github-tools"
    ],
    "policy_results": {
      "allowed": false,
      "mcp_decision": {
        "method": "tools/call",
        "name": "delete_repository",
        "decision": "deny",
        "policy_name": "github-tools",
        "matched_rule": "delete_*",
        "rule_type": "denied_tools"
      },
      "mcp_client": {
        "name": "claude-code",
        "version": "2.1.0"
      }
    },
    "namespace_id": "root"
  },
  "error": "1 error occurred:\n\t* permission denied\n\n"
}
```

### An MCP call denied by a condition

The tool itself was permitted; the **arguments** were not. Since argument constraints are
expressed as a CEL `condition` over `call.args`, the refusal arrives as
`rule_type: "condition"`, with the decision nested on `mcp_decision.condition` and keyed by
the `call.args.*` paths the expression read.

Given this policy:

```hcl
path "mcp/gateway/payments/*" {
  methods { allowed = ["tools/call"] }
  tools   { allowed = ["create_transfer"] }
  condition = "call.args.amount <= 1500 && call.args.currency in ['USD','EUR']"
}
```

a call asking to move 9000 GBP records:

```json
{
  "type": "response",
  "timestamp": "2026-09-16T11:14:22.660185Z",
  "request": {
    "id": "host.local/Kp3nZ2wQxT-000209",
    "operation": "create",
    "path": "role/payments-agent/gateway/",
    "mount_point": "mcp/",
    "mount_type": "mcp",
    "mount_class": "provider",
    "method": "POST",
    "client_ip": "10.4.2.19",
    "namespace_id": "root",
    "streamed": true
  },
  "response": {
    "status_code": 403
  },
  "auth": {
    "token_id": "wtkn_1c7a...",
    "principal_id": "agent-11",
    "role_name": "payments-agent",
    "policies": [
      "payments-tools"
    ],
    "policy_results": {
      "allowed": false,
      "mcp_decision": {
        "method": "tools/call",
        "name": "create_transfer",
        "decision": "deny",
        "policy_name": "payments-tools",
        "matched_rule": "",
        "rule_type": "condition",
        "condition": {
          "decision": "deny",
          "expression": "call.args.amount <= 1500 && call.args.currency in ['USD','EUR']",
          "inputs": {
            "call.args.amount": "9000",
            "call.args.currency": "GBP"
          }
        }
      },
      "mcp_client": {
        "name": "claude-code",
        "version": "2.1.0"
      }
    },
    "namespace_id": "root"
  },
  "error": "1 error occurred:\n\t* permission denied\n\n"
}
```

The argument values land in `inputs`, in clear, which is what makes the refusal
self-explanatory.

:::caution[MCP condition inputs cannot be salted per key]
Per-input salting is implemented for the **path-level** condition
(`auth.policy_results.condition.inputs.<key>`) only. The salter has no case for
`mcp_decision`, so a `salt_fields` entry under
`auth.policy_results.mcp_decision.condition.inputs` matches nothing — and unmatched
`salt_fields` entries are skipped silently, so it will look configured while writing the
value in clear.

If a tool argument is sensitive enough that it must not appear in the log, drop the whole
subtree with `omit_fields` rather than assuming it is hashed.
:::

A condition that *errors* rather than returning false is a different record:
`rule_type` becomes `condition_error` and `condition.error_kind` names the failure. Both
deny — conditions fail closed — but they call for different fixes, so they are recorded
distinctly.

### A login

`auth_result` describes the token that was issued, including the credential spec the role
bound to it.

Note how little is in `auth` here. A login has no *caller* token entry — the token is what the
operation produces — so the fields that come from one (`token_id`, `token_ttl`, `expires_at`,
`created_by_ip`) are absent. **Attribute logins through `response.auth_result`, not `auth`.**

```json
{
  "type": "response",
  "timestamp": "2026-09-16T11:00:02.551903Z",
  "request": {
    "id": "host.local/Kp3nZ2wQxT-000101",
    "operation": "create",
    "path": "login",
    "mount_point": "auth/jwt/",
    "mount_type": "jwt",
    "mount_class": "auth",
    "method": "POST",
    "client_ip": "10.4.2.19",
    "namespace_id": "root"
  },
  "response": {
    "status_code": 200,
    "auth_result": {
      "token_type": "warden_token",
      "principal_id": "agent-7",
      "role_name": "prod-agent",
      "policies": [
        "anthropic-restricted"
      ],
      "token_ttl": 3600,
      "credential_spec": "anthropic-ops"
    }
  },
  "auth": {
    "policy_results": {
      "allowed": true
    }
  }
}
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
- Once **any device is registered**, Warden **fails closed** — a request is served
  only if it can be audited. If every enabled device fails to write, the request
  is rejected rather than processed silently.

With several devices enabled, entries are broadcast to all of them and the
operation succeeds as long as **at least one** writes successfully. So a single
flaky sink degrades but does not block; losing *all* of them does.

> **The [dev server](/concepts/dev-server/) ships with zero audit devices** — it runs
> fail-open and unaudited, which is fine for local work and unacceptable in
> production. Enabling a device is a required step in any real deployment.

## Scope

Audit devices live in the **root namespace** and are **global**: every
namespace's traffic is logged to the same devices, and each entry records the
namespace it came from. Managing devices is therefore a root-namespace,
operator-level operation, not something a tenant configures.

## See Also

- [Policies](/concepts/policies/) — the authorization decisions recorded in each entry.
- [MCP](/concepts/mcp/) — the rule types `mcp_decision` reports.
- [Credentials](/concepts/credentials/) — what "credential issued" in the log refers to.
- [Tokens](/concepts/tokens/) — the identity fields logged per request.
- [Namespaces](/concepts/namespaces/) — recorded per entry; devices are root-scoped.
- [Audit Devices](/audit-devices/) — setup guides for enabling and configuring a device.
- [Configuration → Audit](/configuration/audit/) — declaring devices at startup in the config file.
- [Dev Server](/concepts/dev-server/) — ships unaudited (fail-open).
