---
title: "Upgrading from v0.18.0"
description: "Breaking changes to migrate when moving off v0.18.0 — verified-only actors, GitHub mint_method, and the reshaped RFC 8693 exchange."
---

Three changes since **v0.18.0** need action on upgrade. Work through them before rolling
the new binary out; each is a small, mechanical migration.

## 1. `X-Warden-On-Behalf-Of` removed; actors are verified-only

The self-reported `X-Warden-On-Behalf-Of` request header is gone. The audit/policy
**actor chain** now has a single source — the cryptographically-verified RFC 8693 `act`
claim on the caller's token — so every actor is verified and the `verified` field is
dropped everywhere.

**Migrate CEL conditions.** A `condition` that references `a.verified` now **fails closed**
(the request is denied). Rewrite:

```diff
- condition = "token.actors.all(a, a.verified)"
+ condition = "size(token.actors) > 0"
```

Note the empty-chain semantics also flip: the old expression was vacuously *true* (allow)
for a token with no actors; the rewrite is *false* (deny). If you did **not** mean to
require an actor — the old expression allowed every request, since it also passed when the
chain was empty — simply **drop the condition**.

**Audit shape.** Audit `actors[]` objects lose the `"verified"` key (`{subject, verified}`
→ `{subject}`).

## 2. GitHub specs select the credential with `mint_method`

The `github` driver now reads a required spec-level **`mint_method`** (`app` | `pat`),
matching every other driver's convention. The old `auth_method` key is rejected on a
`github` spec.

```diff
- warden cred spec update my-github-spec -config=auth_method=app
+ warden cred spec update my-github-spec -config=mint_method=app
```

GitLab is unaffected — it legitimately uses both keys.

## 3. RFC 8693 token exchange reshaped around the user

The token-exchange subject/actor model is reworked so every forwarded token is trusted at
its source; the caller-supplied, per-request-validated header path is gone. Several keys
change on `token_exchange` specs and sources.

- **`auth_token` → `agent_identity`.** The `subject_token_source` / `actor_token_source`
  value `auth_token` is renamed (same meaning — the agent's verified inbound JWT). This is
  the **highest-volume migration**: rename it on every exchange spec.

  ```diff
  - -config=subject_token_source=auth_token
  + -config=subject_token_source=agent_identity
  ```

- **The `header` token source is removed.** The `subject_token_source` / `actor_token_source`
  value `header` — which read the caller-supplied `X-Warden-Subject-Token` /
  `X-Warden-Actor-Token` request headers as an *unverified* token — is gone.
  Agent-acting-for-a-user delegation now uses **`subject_token_source=user_identity`**, which
  forwards the secondary [user principal's](/concepts/delegation/) own validated credential as
  the RFC 8693 `subject_token`. Configure the user principal with a `user_auth_path` (see
  [Delegation](/concepts/delegation/)).

- **Removed subject-trust keys.** The keys that pinned trust for a header-sourced token —
  `subject_issuer` / `subject_audience` / `subject_jwks_url` / `subject_oidc_discovery_url` —
  are removed along with the `header` source.

- **Delegation rule.** `actor_token_source ≠ none` now requires
  `subject_token_source=user_identity`.

- **Audit metadata.** The credential-metadata keys `subject_verified` / `actor_verified`
  are no longer emitted (the token-origin concept is gone).

**Fail-closed on upgrade.** A create/update carrying a retired value is rejected at write
time; a **persisted** spec with one **fails closed at mint** (naming the retired value)
rather than minting without exchange. So migrate specs before they are next used. The
`X-Warden-Subject-Token` / `X-Warden-Actor-Token` request headers are simply no longer read.

See the [Token Exchange](/credential-drivers/token-exchange/) and
[Delegation](/concepts/delegation/) pages for the new model.

---

:::note[Main-branch trackers only]
Two changes landed and were superseded *after* v0.18.0, so a released v0.18.0 operator
never saw them and needs no migration: the OIDC-issuer `azure_blob` publisher dropping
`account_key` for a service principal, and the AWS `sts_assume_role_web_identity` mint
method being folded into `sts_assume_role` + `auth_method=oidc_federation`. If you track
`main`, update those in place.
:::
