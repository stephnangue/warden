---
title: "JWT"
---

The JWT auth method admits workloads that carry a **JSON Web Token**. It verifies the token's signature against a key source you configure, checks its issuer, audience and age, and records what it verified as **facts**. The mount holds (or fetches) the issuer's public keys itself, so no call is made to the issuer per request. It grants nothing: [groups](/identity/groups/) match the facts and grant [roles](/identity/roles/), on every request.

This is the auth method to reach for when:

- Your workloads carry tokens issued by an **OIDC provider** (Auth0, Okta, Keycloak, Google, Azure AD, GitHub Actions OIDC, GitLab CI OIDC, Forgejo, Hydra, Dex, …) and you want those tokens accepted as they are.
- You have a fixed set of issuer keys (PEM-encoded RSA or ECDSA) and no JWKS endpoint to publish them.
- You want roles granted from claims, such as a `tenant` claim, a repository name, or a scope.

If your workload's identity is a Kubernetes ServiceAccount token, prefer the [`kubernetes`](/auth-methods/kubernetes/) auth method: it checks the token through the issuing cluster's TokenReview and avoids distributing keys. The JWT method works for ServiceAccount tokens too (the cluster's `/openid/v1/jwks` endpoint is a valid JWKS source), but only when that endpoint is reachable from Warden, which hardened distributions often make awkward.

If your workloads present **SPIFFE identities** (an X.509-SVID or a JWT-SVID), use the [`spiffe`](/auth-methods/spiffe/) auth method. It verifies the SVID against a trust-domain bundle and enforces the SPIFFE audience rules.

People signing in to run the CLI use the [`oidc`](/auth-methods/oidc/) auth method instead.

Coming from v0.21.0, where roles were bound on the auth mount? See [Upgrading from v0.21.0](/upgrade/from-v0-21/).

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- One of:
  - An **OIDC issuer** with a discovery endpoint (the issuer URL; Warden appends `/.well-known/openid-configuration`).
  - A standalone **JWKS endpoint** (a URL serving the issuer's public keys as a JSON Web Key Set).
  - A set of **PEM-encoded RSA or ECDSA public keys**, when no JWKS endpoint is reachable.
- The **audience** your issuer puts in tokens meant for Warden. An agent mount refuses to run without one.
- The [policies](/concepts/policies/) the role you grant will carry. Admitting a token grants no access on its own.

## Step 1: Configure the Key Source

Enable the auth method:

```bash
warden auth enable jwt
```

This mounts at `auth/jwt/`. For several JWT mounts with different key sources, one per tenant or per IdP, name each with `-path`:

```bash
warden auth enable -path=jwt-tenant-a jwt
warden auth enable -path=jwt-tenant-b jwt
```

`-path` takes the mount name only; the CLI adds the `auth/` prefix.

Then configure one, and only one, of the three key sources. A write that leaves the mount with none, or with more than one, is refused.

**OIDC discovery**, the common case, for any provider that publishes `/.well-known/openid-configuration`:

```bash
warden write auth/jwt/config '{
  "oidc_discovery_url": "https://accounts.google.com",
  "bound_issuer": "https://accounts.google.com",
  "bound_audiences": ["my-warden-instance"]
}'
```

**JWKS endpoint**, for issuers that publish a JWKS URL but no discovery document:

```bash
warden write auth/jwt/config '{
  "jwks_url": "https://issuer.example.com/.well-known/jwks.json",
  "bound_issuer": "https://issuer.example.com",
  "bound_audiences": ["warden"]
}'
```

Warden fetches the discovery document or the JWKS before it stores the configuration, so the URL must be reachable from the server when you write it.

**PEM values.** A CA bundle or a public key cannot sit in a JSON argument as it is: it spans lines, and its base64 often holds `=`, which makes `warden write` read the argument as `key=value` pairs. Build the JSON with `jq` and pass it on stdin. For an issuer whose TLS chain is not in the system roots:

```bash
jq -n --rawfile ca internal-ca.pem '{
  "oidc_discovery_url": "https://issuer.internal.example.com",
  "oidc_discovery_ca_pem": $ca,
  "bound_issuer": "https://issuer.internal.example.com",
  "bound_audiences": ["warden"]
}' | warden write auth/jwt/config
```

`jwks_ca_pem` does the same for a JWKS endpoint.

**Static PEM public keys**, for air-gapped clusters or fixed issuers where neither discovery nor JWKS is reachable. List two keys while the issuer rotates, so tokens signed with either are admitted:

```bash
jq -n --rawfile old issuer-2025.pem --rawfile new issuer-2026.pem '{
  "jwt_validation_pubkeys": [$old, $new],
  "bound_issuer": "https://issuer.example.com",
  "bound_audiences": ["warden"]
}' | warden write auth/jwt/config
```

**Quickstart (Ory Hydra).** The provider guides use the local [dev setup](/provider-backends/local-dev-setup/), whose bundled Hydra publishes a JWKS endpoint. Point the mount at it, with the audience the client in [Obtaining a JWT](#obtaining-a-jwt) asks for:

```bash
warden auth enable jwt
warden write auth/jwt/config '{
  "jwks_url": "http://localhost:4444/.well-known/jwks.json",
  "bound_issuer": "http://localhost:4444",
  "bound_audiences": ["warden"]
}'
```

## Step 2: Say What the Mount Admits

A write merges onto the stored configuration: keys you leave out keep their value. These keys decide which tokens are admitted:

- `bound_issuer`: the value the token's `iss` must equal. Set it on every real deployment. Without it, any token signed by a key your source serves is admitted.
- `bound_audiences`: the audiences a token must carry, any one of them. **Required** on a mount that admits agents: without it, a token the same issuer minted for any other service would be admitted. A write that leaves an agent mount without one is refused.
- `bound_subject`: the value the token's `sub` must equal. Useful on a mount meant for a single workload.
- `bound_claims`: a map of claim to required value. A token missing one of the claims, or carrying a different value, is refused. Values compare with their JSON type, so `1` does not match `"1"`.
- `max_age`: the maximum age of a token, from its `iat`, such as `15m`. A token older than that, or without an `iat`, is refused.

And these say what the mount records about a token it admits:

- `entity_kind`: `agent` (the default) or `human`. A `human` jwt mount admits the user an agent acts for, on a provider's `user_auth_path` (see [Delegation](/concepts/delegation/)).
- `facts`: the claims the mount publishes beyond its built-in facts, as a map from claim to fact name.
- `alias_name_source`: the fact whose first value is the caller's **native identity**. Defaults to `sub`.
- `user_claim`: the claim recorded as the caller's principal, in audit and as `agent.principal` in policy. Defaults to `sub`.

A mount for agents of one tenant, which publishes two claims as facts and takes the native identity from the client ID:

```bash
warden write auth/jwt/config '{
  "oidc_discovery_url": "https://idp.example.com",
  "bound_issuer": "https://idp.example.com",
  "bound_audiences": ["warden"],
  "max_age": "15m",
  "entity_kind": "agent",
  "facts": {
    "client_id": "client",
    "/tenant/id": "tenant"
  },
  "alias_name_source": "client"
}'

warden read auth/jwt/config
```

### Facts a token proves

Every admission carries `mount` (here `auth/jwt/`) and `kind` (`agent`), plus the token's `sub`, `iss` and `aud`. Every other claim stays invisible to groups and policy until `facts` names it.

A source in `facts` is a claim name (`client_id`), or a JSON Pointer into nested claims (`/tenant/id`, `/scp/0`, `/realm_access/roles`). A claim that is a JSON array gives one value per element; a string is one value, commas included. Fact names use lowercase letters, digits and `_ . : / -`; `mount` and `kind` are reserved, and a mount maps at most 32 facts. A write of `facts` replaces the whole map, and an empty map clears it.

Mapped facts also reach [CEL conditions](/concepts/cel-conditions/) as `agent.metadata.<name>`, the values of a multi-valued fact joined with commas. With the mapping above, a policy can gate a path with `condition = "agent.metadata.tenant == 'acme'"`. The built-in facts are not in `agent.metadata` unless you map them to themselves (`"sub": "sub"`).

### The native identity

The native identity is the one value that names the caller at this mount. It is what an [entity](/identity/entities/) claims when you register the agent, and what audit names an unregistered caller by. `alias_name_source` may name any fact the mount publishes, built-in or mapped. Pick one that is stable and unique for the workload: a client ID is often a better choice than a `sub` an IdP derives per session. A change applies to tokens admitted after it.

## Step 3: Create a Role

A role names what a caller may do: its policies, an optional credential spec Warden mints from, and how discovery describes it. Roles live in the namespace, not on the mount, so one role can be granted through several mounts.

```bash
warden role create inventory-agent -json '{
  "description": "Reads and updates the inventory service",
  "policies": ["inventory-read", "inventory-write"],
  "cred_spec_name": "inventory-api",
  "provider_path": "inventory/"
}'
```

`provider_path` names the provider mount the role is used with; the [discovery server](/concepts/discovery-and-skills/#discovering-roles) builds the role's URL from it. See [Roles](/identity/roles/) for every field.

## Step 4: Grant the Role with a Group

Nobody holds `inventory-agent` yet. A **virtual group** grants it to every caller whose facts match one of its rules. Every rule names the mounts it trusts in `mount`:

```bash
warden identity group create inventory-agents -json '{
  "type": "virtual",
  "description": "Inventory agents of the acme tenant",
  "roles": ["inventory-agent"],
  "rules": [
    {
      "mount": ["auth/jwt/"],
      "kind": ["agent"],
      "tenant": ["acme"],
      "client": ["inventory-*"]
    }
  ]
}'
```

A token from this mount whose `tenant` is `acme` and whose `client` starts with `inventory-` may now ask for `inventory-agent`. Within a rule every selector must match; across rules any one is enough. `*` matches any run of characters except `/`. The full rule syntax is on [Groups](/identity/groups/).

Once an entity claims an agent's native identity, virtual groups no longer apply to it: it holds only what its entity's [static groups](/identity/groups/#static-groups) grant. See [What a claim changes](/identity/entities/#what-a-claim-changes) before you register an agent that already works through a virtual group.

## Step 5: Point a Provider at the Mount

Workloads never log in. The workload sends its JWT as `Authorization: Bearer` on every request, and Warden admits it in-line through the auth mount the path names:

1. On a provider's gateway, the mount is the provider's `auto_auth_path`. Elsewhere it is the namespace's `auto_auth_path`.
2. Warden verifies the token against the mount's keys and bindings, or reuses the admission it cached for this token.
3. The groups that match the facts decide whether the role the request names is granted.
4. The role's policies decide the call.

Set `auto_auth_path` on the provider the workload reaches, here a [`rest`](/provider-backends/rest/) provider mounted at `inventory/`:

```bash
warden write inventory/config '{
  "base_url": "https://inventory.internal.example.com",
  "auto_auth_path": "auth/jwt/"
}'
```

The workload then names the role in the URL:

```bash
curl -H "Authorization: Bearer $JWT" \
     "${WARDEN_ADDR}/v1/inventory/role/inventory-agent/gateway/<upstream-path>"
```

The role can also come from the `X-Warden-Role` header or the provider's `default_role`. A request that selects no role is refused with `400` before the token is checked. See [How a request selects a role](/identity/roles/#how-a-request-selects-a-role).

The first request with a given token is verified by the mount; the requests that follow reuse that admission until the token expires or the mount's `token_ttl` (default one hour) runs out, whichever comes first. The role is decided again on every request, so an edit to a group or a role applies from the next one.

## Obtaining a JWT

The workload gets its JWT from your identity provider, the same one whose keys back the mount's [key source](#step-1-configure-the-key-source). How depends on the provider: OAuth2 client credentials, a CI runner's OIDC token, a device flow, and so on. Ask for a token whose audience is one of the mount's `bound_audiences`.

For the local [dev setup](/provider-backends/local-dev-setup/), register a Hydra client that may ask for the `warden` audience:

```bash
curl -s -X POST http://localhost:4445/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "inventory-agent",
    "client_secret": "agent-secret",
    "grant_types": ["client_credentials"],
    "response_types": [],
    "scope": "api:read api:write",
    "audience": ["warden"],
    "token_endpoint_auth_method": "client_secret_post"
  }'
```

Then issue a token through the client-credentials grant:

```bash
export JWT=$(curl -s -X POST http://localhost:4444/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=inventory-agent&client_secret=agent-secret&scope=api:read api:write&audience=warden" \
  | jq -r '.access_token')
```

The workload presents `$JWT` on every gateway request, as `Authorization: Bearer` or through the credential field each provider guide documents.

## Discovering Roles

An agent does not need role names in advance. The MCP discovery server's `list_roles` tool returns the roles groups grant the presented token, each with its description, skill and URL; see [Discovery and Skills](/concepts/discovery-and-skills/#discovering-roles). Outside MCP, the same answer comes from:

```bash
curl -H "Authorization: Bearer $JWT" \
  "${WARDEN_ADDR}/v1/sys/introspect/roles"
```

The response is `{roles: [{name, description, skill, provider_path}, ...], warnings: [...]}`. Warden admits the token at each auth mount a role of the namespace is reached through and lists the roles a group grants it there. It is a hint, not a grant: each request is still decided on its own.

## Delegation Chain (RFC 8693 `act` Claim)

RFC 8693 §4.1 defines an `act` claim that attests a delegation chain: this token represents X, acting on behalf of Y, acting on behalf of Z. When a token carries one, Warden reads the chain (up to a depth of 4, to guard against pathological tokens) and records it with the request. Because the issuer signed the token, the chain is attested. Audit entries carry the full chain, and policies read it as `agent.actors`.

No configuration is needed. See [Delegation](/concepts/delegation/).

## Configuration Reference

Exactly one of `oidc_discovery_url`, `jwks_url` or `jwt_validation_pubkeys` must be set. Lists take a JSON array or a comma-separated string.

| Field | Required | Description |
|---|---|---|
| `oidc_discovery_url` | one of three | OIDC issuer URL. Warden appends `/.well-known/openid-configuration` and fetches the keys from the JWKS it names. |
| `oidc_discovery_ca_pem` | No | PEM CA bundle for the discovery endpoint, when its TLS chain is not in the system roots. |
| `jwks_url` | one of three | JWKS endpoint URL, for issuers without a discovery document. |
| `jwks_ca_pem` | No | PEM CA bundle for the JWKS endpoint. |
| `jwt_validation_pubkeys` | one of three | PEM-encoded RSA or ECDSA public keys. List several to overlap a key rotation. |
| `bound_issuer` | No (strongly recommended) | Value the token's `iss` must equal. |
| `bound_audiences` | **Yes**, when `entity_kind` is `agent` | Audiences a token must carry, any one of them. |
| `bound_subject` | No | Value the token's `sub` must equal. |
| `bound_claims` | No | Map of claim to required value, compared with its JSON type. |
| `max_age` | No | Maximum age from the token's `iat`, such as `15m`. A token older than that, or without an `iat`, is refused. Empty or `0` leaves it unset. |
| `user_claim` | No (default `sub`) | Claim recorded as the caller's principal. A token without it is refused. |
| `token_ttl` | No (default `1h`) | How long an admission is reused before the token is verified again; never past the token's `exp`. |
| `entity_kind` | No (default `agent`) | `agent` or `human`. |
| `facts` | No | Map of claim name or JSON Pointer to the fact name it is published as. At most 32 entries; names use `a-z 0-9 _ . : / -`, never `mount` or `kind`. A write replaces the whole map. |
| `alias_name_source` | No (default `sub`) | The fact whose first value is the native identity: `sub`, `iss`, `aud`, or a mapped fact. An empty value restores the default. |

The built-in facts are `mount`, `kind`, `sub`, `iss` and `aud`. Tokens must be signed with RS256, RS384, RS512, ES256, ES384 or ES512, and carry an `exp`.

## Troubleshooting

**A gateway request returns "authentication failed" with no detail.** By design, every admission failure gets the same answer, so a response cannot tell a caller which check failed. The server log carries the reason: a signature mismatch, an expired token, a missing bound claim, an audience mismatch, `max_age` exceeded, no `user_claim` in the token. Look at the log at the time of the failed call.

**A config write fails with `bound_audiences is required on agent mounts`.** Set `bound_audiences` to the audience your issuer puts in tokens meant for Warden, or set `entity_kind` to `human` for a mount that admits users.

**A config write fails with `oidc_discovery_url is not reachable` or `jwks_url is not reachable`.** Warden fetches the URL before it stores the configuration. Make sure it is reachable from the Warden server, and that `oidc_discovery_ca_pem` or `jwks_ca_pem` covers its TLS chain when it is not a public CA. For air-gapped clusters, use `jwt_validation_pubkeys`.

**A config write refuses a key.** Keys that bound roles to the mount were removed. The error names each one and what replaced it.

**`role "inventory-agent" is not assumable through auth/jwt/: no group grants it to this caller`.** The token was admitted, but no group matched it. Check that the rule's `mount` is the mount's path with its trailing slash (`auth/jwt/`), that each fact the rule names is built in or mapped in `facts`, and that the token carries the values the rule expects. The audit entry's `role_denied_reason` and `groups` say what matched. If an entity claims the caller's native identity, only its static groups apply.

**A rule on a mapped fact never matches.** The rule names the fact name, not the claim (`tenant`, not `/tenant/id`). A JSON Pointer needs its leading `/`. A claim that holds an object gives no value; point into it instead.

**Tokens from one IdP pass, tokens from another fail, or the reverse.** Pin `bound_issuer` to the expected `iss`. Without it, any token signed by a key your source returns passes the signature check, which can admit tokens the IdP signed for other consumers.

**`max_age` refuses every token.** The token must carry an `iat` for the check to work. If your IdP omits it, configure the IdP to emit it or clear `max_age`.

**`admission token presented explicitly; present the credential instead`.** The request presented, as a Warden token, what an explicit login against the mount returned. A login hands out nothing to present later: send the JWT itself as `Authorization: Bearer` on every request.

## See Also

- [Authentication](/identity/authentication/): auth mounts, facts and native identities.
- [Groups](/identity/groups/) and [Roles](/identity/roles/): how an admitted caller is granted what it may do.
- [Entities](/identity/entities/): registering agents in the identity store.
- [Agent Identity](/agent-identity/): how a workload or its sidecar presents this credential to Warden.
- [Auth Methods](/auth-methods/): the other auth methods Warden ships.
