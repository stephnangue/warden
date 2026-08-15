## Warden v0.19.0

v0.19.0 is the **keyless federation** release. Warden can now act as its own **OIDC issuer** — minting short-lived, signed **identity assertions** that describe the caller and publishing the **JWKS / OIDC discovery** to verify them — so an upstream trusts *who the caller is* instead of a secret Warden holds. On top of that, **keyless credential sources** (`auth_method=oidc_federation`) across AWS, Azure, GCP, and OpenBao/Vault store **no cloud secret** at all — each request federates an assertion for a short-lived credential — and **credential chaining** (`secret_spec`) sources any *remaining* standing secret from an external keyless-federated vault per request, so there is no key-trove to breach. The issuer's **signing key can live in an external KMS** (the private key never enters Warden), and a public **publisher** exposes the verification keys to internet-facing clouds without exposing Warden itself. Finally, a second **user principal** lets an agent act **on behalf of a verified human** — natively ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) / [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) / ID-JAG) or, for upstreams with no on-behalf-of flow, via a per-user OAuth token from OpenBao/Vault at fleet scale. Three breaking changes — read **Upgrading** before bumping.

### Breaking Changes

- **RFC 8693 token exchange reshaped around the user.** The `header` token source and its subject-trust keys (`subject_issuer` / `subject_audience` / `subject_jwks_url` / `subject_oidc_discovery_url`) are removed; the `subject_token_source` / `actor_token_source` value **`auth_token` is renamed to `agent_identity`**; and delegation now forwards the end user's own validated credential via **`subject_token_source=user_identity`** (with `actor_token_source=warden_identity` for the on-behalf-of-user shape). A create/update with a retired value is rejected, and a persisted spec carrying one **fails closed at mint**.

- **GitHub credential specs select the credential with `mint_method`, not `auth_method`.** The `github` driver now reads a required spec-level `mint_method` (`app` | `pat`); the old `auth_method` key is rejected. GitLab is unaffected.

- **`X-Warden-On-Behalf-Of` retired; audit/policy actors are verified-only.** The self-reported header is gone — the actor chain now has a single source, the cryptographically-verified RFC 8693 `act` claim. The `verified` field is dropped everywhere, so a CEL `condition` referencing `a.verified` (e.g. `token.actors.all(a, a.verified)`) must become `size(token.actors) > 0`.

### New Features

**Federation & keyless identity**

- **Warden is now an OIDC issuer.** It mints short-lived, signed JWT identity assertions (`sub = wid:<namespaceID>:<mountAccessor>:<principalID>`, plus `warden_*` claims) and publishes the matching JWKS + OIDC discovery, so any upstream that trusts an OIDC issuer — a cloud STS, an IdP, a secrets vault — can verify a caller's identity directly. The issuer fails closed until a signing key is installed, and key rotation retires prior keys into the JWKS so in-flight assertions keep verifying.
- **The signing key can live in an external KMS.** A `signer { }` stanza binds the assertion-signing key to an external KMS (`type = "transit"` today) so the **private key never enters Warden**; the interface is built for more backends.
- **Publishers expose the keys to internet-facing upstreams.** A publisher pushes the discovery + JWKS to a bucket/CDN (`s3`, `gcs`, `azure_blob`, `http_put`, `local_file`) that becomes the `issuer_url` upstreams fetch from — so Warden itself need not be internet-facing — and self-rotates its own write credential.
- **Keyless credential sources — `auth_method=oidc_federation`.** A source can hold no stored cloud secret: on each request Warden federates an identity assertion for a short-lived credential. Ships for AWS (`AssumeRoleWithWebIdentity`, keyless Secrets Manager), Azure (Entra `client_assertion`), GCP (Workload Identity Federation), and OpenBao/Vault (per-request JWT-auth login).
- **Assertion shaping.** `warden_identity` assertions can pin a single downstream resource (`warden_resource`) and carry allowlisted login metadata (`assertion_metadata_claims` → nested `warden_metadata`) for verifier-side least privilege.

**Credential chaining**

- **Chain a spec's secret from another cred spec (`secret_spec`).** A secret-backed provider sources its standing secret from another spec at request time instead of storing it — keyless end-to-end, single-hop, nothing persisted. Includes a generic **`kv2_read` mint method + `key_value` credential type**, an opt-in source-scoped cache (`secret_cache_ttl`), and support for sourcing the **`token_exchange` client secret** this way.

**User principal & acting on behalf of a human**

- **Per-user credential chaining via secondary transparent authentication.** A request can carry a second, per-request user credential (default header `X-Warden-User-Token`) that Warden resolves into a first-class user principal — identity-only today. A `warden_identity` spec can disclose the user under a nested `warden_user` claim, and a per-user `secret_path` / `credential_name` template (`{{user.<claim>}}`) selects a secret or OAuth token scoped to the verified user — so an agent acts as the human, even against upstreams with no native on-behalf-of flow.

### Upgrading

Three changes need action; each is a small, mechanical migration. See the [Upgrading from v0.18.0](https://wardengateway.com/upgrade/from-v0-18/) guide for the full detail.

- **CEL actor conditions:** rewrite `token.actors.all(a, a.verified)` → `size(token.actors) > 0` (note the empty-chain semantics flip from allow to deny — drop the condition entirely if you did not mean to require an actor).
- **GitHub specs:** rename `-config=auth_method=<app|pat>` → `-config=mint_method=<app|pat>`.
- **Token-exchange specs:** rename `subject_token_source=auth_token` → `agent_identity`; re-express a header-sourced delegation as `subject_token_source=user_identity` (+ `actor_token_source=warden_identity`) with a `user_auth_path` configured; drop the removed `header` source and `subject_*` trust keys.
