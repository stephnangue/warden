## Warden v0.22.0

v0.22.0 is the **agent identity and governance** release: register every agent, name the team that answers for it, and refuse the ones nobody claimed. Every caller already had a native identity — the JWT subject, certificate, service account or SPIFFE ID its auth mount verified. What is new is the **entity**: a record in Warden's identity store that claims an agent's native identities and names its **sponsor**, a group of humans who accepted it. Entities are optional. Under the default `unknown_aliases=observe`, the audit log tells you which agents `deny` would refuse; switch to `deny` and unclaimed or ungoverned agents are refused. Suspend an entity and every native identity it claims is refused from the next request.

Roles are no longer bound at login. A login admits a credential and names the facts its mount verified, and groups grant roles one request at a time: **virtual groups** by rules over those facts, **static groups** by listing governed entities. A **`governed_only`** role is never granted by a rule.

People sign in with **`warden login`** through the new **`oidc`** auth method and hold roles through their IdP's claims, without becoming entities. Four **built-in operator roles** — `warden-admin`, `warden-provider-admin`, `warden-security-admin` and `warden-viewer` — cover the usual operator jobs, and none ever reaches a data plane.

Discovery now answers to policy and audit like every other request. Agents reach **Microsoft 365 as the user** through Entra on-behalf-of and the new **msgraph** provider. Azure sources can authenticate with a **certificate** whose key stays in a KMS, oauth2 sources gain `client_secret_basic`, `private_key_jwt` and KMS-signed assertions, and **Bedrock** model calls go through the aws gateway. Policy compilation is about 2.7 times cheaper, and the token and credential caches are sized by the bytes they hold.

**Twelve breaking changes — read Upgrading before you bump.**

### Breaking Changes

- **Auth roles are removed.** `auth/<mount>/role/*` answers `410`; roles live at `sys/roles/<name>` and groups grant them per request. Logins take no role, and the role-era mount keys (`default_role`, `groups_claim`, `group_policy_prefix`, `metadata_claims`, `metadata_mappings`, `token_type`) and the provider's `user_auth_role` are refused.
- **Agent jwt and spiffe mounts require `bound_audiences`**, and `max_age` moves from the role to the mount.
- **Token types are `identity_token` and `service_token`** (`wds.`). Root and other `cws.` tokens no mount issued resolve until they expire; tokens a v0.21.0 auth mount issued are refused, so agents log in again.
- **Reserved names**: policies `default` and `default-*`, roles `warden-*`.
- **Discovery runs through the request path**: authorized by built-in policies, audited, `401` without a credential, `503` when no mount admitted it and one could not decide, batches capped at 50.
- **The MCP `resources` family covers `skills/get` and `resources/directory/read`.** A contract allowing every method with no `resources` block now refuses them.
- **gcp and azure forward only to `allowed_host_suffixes`**, and azure refuses Graph `$batch`.
- **Policy names and request paths have one spelling**: non-canonical policy names and percent-encoded dot or empty segments get `400`.
- **Credential sources are held to their own config**: `hvault` edits need `auth_method`, `wid:` user principals are refused, impersonation and routing headers are stripped, and edits reach live sessions.
- **Audit has a floor**: no headers or bodies, `salt_fields` extends the default salting, unknown paths are refused at enable.
- **Nested namespaces written through an ancestor were misplaced** — recreate them; no repair ships.
- **Mixed-version clusters**: a v0.21.0 node cannot read PS256 capabilities, roles or groups, and the token cache holds about 113,000 service tokens at its default 100 MiB.

### Security

- **Canonical policy names and request paths** close two inherited upstream policy advisories.
- **SigV4 upstreams stay on AWS hosts**, and gcp and azure carry a token only to allowed hosts.
- **Every stored secret is masked on read**, and an `hvault` source never inherits the server process's environment.
- **`sys/step-down` requires root or sudo**, and discovery is authorized and audited.
- **No credential reaches an audit entry or log in clear.**
- **The `wid:` prefix is reserved for agents**, and Kubernetes impersonation and Elastic run-as headers are stripped.
- **Skills on MCP gateways are gated by URI**, and Graph `$batch` is refused.

### New Features

**Agent identity and governance**

- **Native identities** on every admission, and **entities** that claim them, managed with `warden identity entity` and `warden identity alias`; `entity list -ungoverned` shows the agents nobody answers for.
- **Sponsors**: a virtual group of humans who accept an agent, and can read, suspend and hand it over with `warden identity sponsor` and no Warden role.
- **`unknown_aliases`**: `observe` records why `deny` would refuse each request; `deny` refuses unclaimed and ungoverned agents.
- **Static groups** and **`governed_only` roles**: a claimed agent holds only what its entity's static groups grant.

**Roles, groups and people**

- **Namespace roles and virtual groups**, with mounts naming the facts they verify, and group writes that name their type.
- **The `oidc` auth method, ticket tokens, and `warden login | logout | role use | print token`.**
- **Built-in operator roles**, turned on per namespace by its parent with `enable_builtin_roles`, and **`request.data_plane`** in CEL.

**Discovery under policy**

- **Built-in `default-cbp`, `default-mcp` and `default-sponsor` policies**, and policy compilation about 2.7 times cheaper.

**Microsoft 365, Entra and credentials**

- **The msgraph provider** and **Entra on-behalf-of**, with challenges MSAL understands.
- **Azure certificate authentication**, with a local or KMS-held key.
- **oauth2 `client_secret_basic`, `private_key_jwt` and `kms_private_key_jwt`**, and an issuer audience on oauth2 and token_exchange.
- **Bedrock Runtime through the aws gateway**, bounded by the mount's `timeout`.
- **`token_cache_megabytes` and `credential_cache_megabytes`**, and pooled copy buffers on every proxied response.

### Fixed

- **The chained-secret cache holds 10,000 secrets**; it held 175.
- **A transit seal configured in HCL works** — it failed in every release up to v0.21.0.
- **The root token is recognised after a restart.**
- **Access backends authenticate agents implicitly**, without minting each other's credential.
- **Credential lifetimes and leases are bounded in one place**, a create is never replayed after an ambiguous failure, and one caller's cancellation no longer fails the others.

### Upgrading

Twelve changes need action. Work through [Upgrading from v0.21.0](https://wardengateway.com/upgrade/from-v0-21/) before rolling out the binary.

- **Export your auth roles before upgrading** — after it, their paths answer `410`. Convert each into a `warden role create` and a `warden identity group create` with one rule per mount, naming the claims it matched as mount `facts`.
- **Agents holding v0.21.0 login tokens log in again**, and long-lived `cws.` service tokens should be rotated.
- **Update the seeded `troubleshooting` skill** with `warden skill update troubleshooting -body-file <file>`: existing clusters keep their copy.
- **Recreate nested namespaces** created, updated or deleted through an ancestor.
- **Set `bound_audiences` on agent jwt and spiffe mounts**, add non-default Azure hosts to `allowed_host_suffixes`, and set `auth_method` on every `hvault` source.

A ticket cannot be revoked before it expires; disabling its `oidc` mount ends every session it issued. Graph `$batch` is refused. A sponsor is always a group, never a single person.
