---
title: "SPIFFE"
---

The SPIFFE auth method authenticates workloads that present a **SPIFFE SVID** — the short-lived identity document a SPIFFE/SPIRE deployment issues to every workload. SPIFFE defines two SVID shapes, and this method accepts **both on the same mount**:

- an **X.509-SVID** — a TLS client certificate, presented over direct mTLS or re-forwarded by a trusted proxy, and
- a **JWT-SVID** — a bearer JWT carried in the `Authorization` header.

A SPIFFE *trust domain* is a single bundle that carries both the X.509 authorities and the JWT signing keys for that domain. Warden anchors trust per trust domain via these bundles — registered statically or fetched through **SPIFFE Federation** — and verifies each presented SVID against the bundle of the SVID's own trust domain. The mount records what it verified as **facts** (the SPIFFE ID, its trust domain and path, the kind of SVID), and the SPIFFE ID is the caller's **native identity**. The mount grants nothing: a [role](/identity/roles/) is granted per request by a [group](/identity/groups/) whose rules match those facts.

This is the auth method to reach for when:

- Your workloads run in a **service mesh or SPIRE deployment** that already mints SPIFFE SVIDs, and you want Warden to consume that identity directly — whether the workload reaches Warden over mTLS (X.509-SVID) or with a bearer token (JWT-SVID).
- You federate identity **across trust domains** (multi-cluster, multi-cloud) and want Warden to trust a remote domain's workloads by fetching its bundle from a federation endpoint.
- You want **one mount** to serve both SVID types rather than splitting SPIFFE X.509 and SPIFFE JWT identity across the `cert` and `jwt` methods.

If your workload's identity is an ordinary OIDC JWT (not a SPIFFE JWT-SVID), use the [`jwt`](/auth-methods/jwt/) method. If it is a plain X.509 client certificate from a classic PKI (not issued under a SPIFFE trust domain), use the [`cert`](/auth-methods/cert/) method. The `cert` method can still accept a SPIFFE X.509-SVID as an ordinary certificate matched on its URI SAN — but only the `spiffe` method verifies it against a trust-domain bundle and accepts the matching JWT-SVID on the same mount.

Coming from v0.21.0? See [Upgrading from v0.21.0](/upgrade/from-v0-21/).

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- A **SPIFFE trust domain** whose bundle you can supply to Warden — either the PEM/JSON bundle bytes directly, or the URL of a SPIFFE Federation bundle endpoint Warden can fetch from.
- For X.509-SVIDs, a way to get the workload's certificate to Warden — direct mTLS termination at the Warden listener, or a reverse proxy that terminates TLS and re-presents the certificate in a forwarding header, listed in the listener's [`trusted_proxies`](/configuration/listener/).
- The **policies** the workload's role will carry. Admitting an SVID grants nothing on its own.

## Step 1: Enable the Method and Register a Trust Domain

Enable the auth method:

```bash
warden auth enable spiffe
```

This mounts at `auth/spiffe/`. Use `-path` to name additional mounts (e.g. one per environment); the CLI prefixes `auth/` automatically.

A `spiffe` mount carries no trust on its own — you register the trust domains it should honour. The simplest case is a **static bundle**: the X.509 authorities (and, for JWT-SVIDs, the JWT signing keys) of the domain, supplied directly.

A bundle's base64 can hold `=`, and `warden write` reads an argument with an `=` in it as `key=value` pairs, so fold the file into JSON with `jq` and pass it on stdin:

```bash
# X.509 authorities as PEM (sufficient for X.509-SVIDs)
jq -n --rawfile pem prod-ca-bundle.pem '{
  "bundle_pem": $pem
}' | warden write auth/spiffe/trust-domain/prod.example.org
```

To accept **JWT-SVIDs** as well, supply a SPIFFE trust-bundle (JWKS) document, which carries both authority types:

```bash
jq -n --rawfile bundle prod-bundle.json '{
  "bundle_json": $bundle
}' | warden write auth/spiffe/trust-domain/prod.example.org
```

A trust-domain write replaces the whole entry: fields you leave out are cleared. Read back a summary (authority counts and subjects, never the raw key bytes) and list the configured domains:

```bash
warden read auth/spiffe/trust-domain/prod.example.org
warden list auth/spiffe/trust-domain
```

A trust domain can be **federated** instead of static — Warden fetches and refreshes the bundle from an endpoint. See [Federation](#federation).

The mount admits an SVID from **any** trust domain it holds, so a mount with several domains admits workloads from all of them. Which of them get a role is the groups' decision (Step 3).

## Step 2: Configure the Mount

The mount configuration says what the mount admits:

```bash
warden write auth/spiffe/config '{
  "bound_audiences": ["warden"],
  "max_age": "10m",
  "token_ttl": "1h",
  "entity_kind": "agent"
}'

warden read auth/spiffe/config
```

- `bound_audiences` — the audiences a **JWT-SVID** must carry, any one of them. On an agent mount it is required: a write that would leave it empty is refused. X.509-SVIDs carry no audience and ignore it. See [The Audience Requirement](#the-audience-requirement-jwt-svid).
- `max_age` — the maximum age of a **JWT-SVID** at admission, from its `iat`. A JWT-SVID older than that, or without an `iat`, is refused. X.509-SVIDs carry no issue time and are not checked.
- `token_ttl` — how long an admission is reused before the SVID is verified again (default `1h`). Always capped by the SVID's own expiry.
- `entity_kind` — `agent` (the default) or `human`.

A config write merges onto the stored configuration: keys you leave out are kept, so a later write need not repeat `bound_audiences`. Until the mount is configured, it admits X.509-SVIDs and refuses every JWT-SVID.

## Step 3: Create a Role and Grant It

A role names the policies a request runs under. It lives in the namespace, not on the mount:

```bash
warden role create inventory-agent -json '{
  "description": "Read and update the inventory",
  "policies": ["inventory-read", "inventory-write"],
  "provider_path": "vault/"
}'
```

`description` and `provider_path` are what the [discovery server](/concepts/discovery-and-skills/#discovering-roles) shows an agent: what the role is for, and the URL to call it at.

Nobody holds the role yet. A virtual group grants it to callers whose facts match its rules. This one grants `inventory-agent` to every workload under `/ns/agents/sa/inventory-…` in the `prod.example.org` trust domain:

```bash
warden identity group create inventory-agents -json '{
  "type": "virtual",
  "description": "Inventory workloads in the prod trust domain",
  "roles": ["inventory-agent"],
  "rules": [
    {
      "mount": ["auth/spiffe/"],
      "trust_domain": ["prod.example.org"],
      "path": ["/ns/agents/sa/inventory-*"]
    }
  ]
}'
```

The same rule serves both SVID types. Every rule names the `mount` it trusts; selectors in one rule must all match, and a group with several rules matches when any one does. See [Selecting Workloads by SPIFFE ID](#selecting-workloads-by-spiffe-id) for the patterns.

## Step 4: Point a Provider at the Mount

A provider's gateway asks the mount named by its `auto_auth_path` to admit the credential. Set it on the provider the workload calls:

```bash
warden write vault/config '{
  "auto_auth_path": "auth/spiffe/"
}'
```

The workload then presents its SVID on every request; there is no login step. The role goes in the URL. A JWT-SVID call:

```bash
curl -H "Authorization: Bearer $JWT_SVID" \
     "${WARDEN_ADDR}/v1/vault/role/inventory-agent/gateway/<upstream-path>"
```

An X.509-SVID call presents the certificate over mTLS, directly to Warden or to a trusted proxy that re-forwards it as `X-SSL-Client-Cert` / `X-Forwarded-Client-Cert`:

```bash
curl --cert workload.pem --key workload-key.pem \
     "${WARDEN_ADDR}/v1/vault/role/inventory-agent/gateway/<upstream-path>"
```

A request can also name its role with the `X-Warden-Role` header, or fall back to the provider's `default_role`. A request that names no role is refused with `400` before its SVID is checked (see [How a request selects a role](/identity/roles/#how-a-request-selects-a-role)).

Warden keeps one cached admission per mount and SVID, so an SVID is verified once and reused until it expires or the mount's `token_ttl` runs out, whichever is first. The role is still checked against the groups on every request, so a group or role change applies from the next one. A login against `auth/<mount>/login` runs the same checks and reports what they verified, but returns nothing to present on later requests.

## Credential Precedence: JWT-SVID Wins

A single request can carry both credentials at once — common in a mesh, where a sidecar makes a forwarded X.509-SVID *ambient* on every call while the workload also sends a JWT-SVID bearer for a specific intent. When both are present, **the explicitly-presented JWT-SVID is used** and the ambient certificate is ignored. This keeps the JWT-SVID path live in a mesh and attributes the request to the identity the workload deliberately presented, rather than silently falling back to the sidecar's certificate. Present only an X.509-SVID (no bearer) to authenticate as the certificate identity.

## The Audience Requirement (JWT-SVID)

SPIFFE mandates that a JWT-SVID be minted for a specific **audience** and that the relying party validate it — without that check, a JWT-SVID issued for service A could be replayed against service B. Warden enforces this fail-closed:

- A JWT-SVID is validated against the mount's `bound_audiences`. A token whose `aud` doesn't include one of them is refused.
- A mount with **no** `bound_audiences` refuses every JWT-SVID. The same mount still admits X.509-SVIDs, which carry no audience.
- A config write that would leave an agent mount without `bound_audiences` is refused.

Set `bound_audiences` to the identifier your workloads request their JWT-SVIDs for (often the Warden instance or the upstream service name). With SPIRE, that is the audience the workload asks the Workload API for, e.g. `spire-agent api fetch jwt -audience warden`.

## Selecting Workloads by SPIFFE ID

Group rules select on the SVID's verified facts. For `spiffe://prod.example.org/ns/web/sa/frontend`:

| Fact | Value |
|---|---|
| `spiffe_id` | `spiffe://prod.example.org/ns/web/sa/frontend` |
| `trust_domain` | `prod.example.org` |
| `path` | `/ns/web/sa/frontend` |
| `svid` | `x509` or `jwt` |

Values are exact strings unless they hold a glob:

- `*` matches any run of characters except `/`, so `/ns/web/sa/*` matches `/ns/web/sa/frontend` but not `/ns/web/sa/frontend/v2`.
- `**` matches across `/`, so `/ns/web/**` matches every path under `/ns/web/`.
- `?` matches exactly one character except `/`.

```bash
warden identity group create frontend -json '{
  "type": "virtual",
  "description": "Web and edge workloads in prod",
  "roles": ["frontend"],
  "rules": [
    {
      "mount": ["auth/spiffe/"],
      "spiffe_id": [
        "spiffe://prod.example.org/ns/web/sa/*",
        "spiffe://prod.example.org/ns/edge/sa/*"
      ]
    }
  ]
}'
```

Because the mount admits every trust domain it holds, pin the domain in each rule: with `trust_domain`, or with a full `spiffe_id` pattern as above. A rule on `path` alone matches the same path in every trust domain of the mount. Add `"svid": ["jwt"]` to a rule to grant the role to JWT-SVIDs only. The full rule syntax is on [Groups](/identity/groups/#rules-and-selectors).

## Federation

A trust domain can be **federated** rather than static: instead of pasting its bundle, you point Warden at the domain's SPIFFE Federation bundle endpoint, and Warden fetches the bundle and refreshes it periodically. This is how you trust workloads from another cluster or cloud whose authorities rotate on their own schedule.

SPIFFE defines two endpoint profiles, and Warden supports both:

**`https_web`** — the bundle endpoint is served over ordinary Web PKI TLS. Warden validates the endpoint's TLS certificate against the system roots (or custom roots you supply via `web_pki_ca_pem`).

```bash
warden write auth/spiffe/trust-domain/remote.example.org '{
  "bundle_endpoint_url": "https://spiffe.remote.example.org/bundle",
  "bundle_endpoint_profile": "https_web"
}'
```

**`https_spiffe`** — the endpoint authenticates itself with its *own* SPIFFE X.509-SVID. This needs the endpoint's expected SPIFFE ID and a **bootstrap bundle** (carrying X.509 authorities) to authenticate that first fetch:

```bash
jq -n --rawfile bundle remote-bootstrap-bundle.json '{
  "bundle_endpoint_url": "https://spiffe.remote.example.org/bundle",
  "bundle_endpoint_profile": "https_spiffe",
  "endpoint_spiffe_id": "spiffe://remote.example.org/spire/server",
  "bundle_json": $bundle
}' | warden write auth/spiffe/trust-domain/remote.example.org
```

Warden refreshes federated bundles in the background on the active node. To force an immediate fetch — after rotating the remote domain's authorities, say:

```bash
warden write auth/spiffe/trust-domain/remote.example.org/refresh '{}'
```

A refresh that can't reach the endpoint fails the call with `502` but keeps the last-good bundle in place, so a transient outage at the remote domain doesn't break admissions for already-fetched authorities. Reading a federated trust domain shows its fetch status (`sequence`, `last_refresh`, `last_error`).

## Facts and Native Identity

Every admission through a spiffe mount carries these facts:

| Fact | Value |
|---|---|
| `mount` | The mount's path in its namespace, e.g. `auth/spiffe/`. |
| `kind` | `agent` or `human`, from `entity_kind`. |
| `spiffe_id` | The verified SPIFFE ID. |
| `trust_domain` | Its trust domain. |
| `path` | Its path. The ID of a trust domain itself has no path, so no `path` fact. |
| `svid` | `x509` or `jwt`: the kind of SVID that carried it. |
| `aud` | A JWT-SVID's audiences. An X.509-SVID has none. |

`facts` can publish one of these fields again under a second name; no other source is accepted, so other JWT-SVID claims are never facts. A mount maps at most 32, and `mount` and `kind` are reserved. Mapped facts also reach [CEL conditions](/identity/cel-conditions/) as `agent.metadata.<name>`; map a field to its own name to expose it unchanged:

```bash
warden write auth/spiffe/config '{
  "facts": {
    "path": "workload",
    "trust_domain": "trust_domain"
  }
}'
```

An SVID for `spiffe://prod.example.org/ns/prod/sa/ci` then carries `agent.metadata.workload == "/ns/prod/sa/ci"` and `agent.metadata.trust_domain == "prod.example.org"`, and a policy can gate a path with `condition = "agent.metadata.trust_domain == 'prod.example.org'"`. A write replaces the whole `facts` map; an empty map clears it.

The **native identity** is always the `spiffe_id`, for both SVID types. A spiffe mount takes no `alias_name_source`: a write that sets it is refused.

## Delegation Chain (RFC 8693 `act` Claim)

RFC 8693 §4.1 defines an `act` claim that attests a delegation chain — "this token represents X, acting on behalf of Y." When a JWT-SVID carries it, Warden extracts the chain (up to a fixed depth of 4) and records it with the admission, so audit entries carry the full chain. Because the trust domain signed the SVID, the chain is inherently attested. No configuration needed; extraction happens automatically when the claim is present.

## Registering the Workload

The steps above grant roles to any SVID that matches the group's rules. To give the workload a record in the identity store, with a description, a sponsor and a state you can suspend, create an [entity](/identity/entities/) and have it claim the SPIFFE ID.

Once an entity claims it, virtual groups no longer apply to the workload: it holds only what static groups listing its entity grant, and only while the entity is governed. So create the entity without a claim, give it a [sponsor](/identity/sponsors/) and a static group, and claim last:

```bash
warden identity entity create inventory-agent -json '{
  "description": "Reads and updates the inventory"
}'

# ... propose a sponsor and list the entity in a static group, then:
warden identity alias add -json '{
  "mount": "auth/spiffe/",
  "name": "spiffe://prod.example.org/ns/agents/sa/inventory-agent",
  "to": "inventory-agent"
}'
```

One entity can claim the same agent's SPIFFE ID and, say, its Kubernetes service account, so it has one record wherever it runs. [Entities](/identity/entities/#rolling-out) walks through the rollout.

## Discovering Roles

An agent that doesn't know which role to ask for asks the MCP discovery server's `list_roles`, which returns each role the groups grant it with its description, skill and URL — see [Discovery and Skills](/concepts/discovery-and-skills/#discovering-roles). Over plain HTTP, the workload presents its SVID:

```bash
# JWT-SVID
curl -H "Authorization: Bearer $JWT_SVID" \
  "${WARDEN_ADDR}/v1/sys/introspect/roles"
```

The response is `{roles: [{name, description, skill, provider_path}, ...], warnings: [...]}`. Warden admits the SVID at each mount a role of the namespace is reached through (its provider's `auto_auth_path`) and lists the roles a group grants it there. A mount that could not decide (no trust bundle loaded, or a JWT-SVID with no `bound_audiences` to check) adds a warning; one that does not admit the SVID is silent. Discovery is a hint, not a grant: each gateway request is admitted and checked against the groups again.

## Revocation and SVID Lifetime

The SPIFFE method does **not** perform X.509 CRL or OCSP revocation checks. This is deliberate and matches the SPIFFE model: SVIDs are short-lived and continuously re-minted, and a compromised authority is handled by rotating the trust domain's bundle (which Warden picks up on its next federation refresh, or immediately on a manual refresh), not by revoking individual SVIDs. There is no revocation configuration surface on the mount.

Two properties keep the blast radius small without revocation:

- **An admission never outlives its SVID.** Warden reuses an admission only until the SVID expires, so a short-lived SVID is verified again soon after.
- **Bundle rotation is the kill switch.** Removing or rotating a trust domain's authorities stops Warden from validating any SVID signed by the old keys — update the bundle (static write or federation refresh) to cut off a compromised authority.

To cut off one workload without touching the bundle, change the group rule that grants it, or register it as an entity and suspend the entity. If you require per-certificate revocation, use the `cert` method with its revocation modes against a classic PKI instead.

## Configuration Reference

### Mount configuration (`auth/<mount>/config`)

| Field | Required | Description |
|---|---|---|
| `bound_audiences` | Yes, on an agent mount | Audiences a JWT-SVID must carry, any one of them. Without it no JWT-SVID is admitted. Ignored for X.509-SVIDs. No entry may be empty. |
| `max_age` | No | Maximum age of a JWT-SVID at admission, from its `iat`, e.g. `10m`. A JWT-SVID older than that, or without an `iat`, is refused. X.509-SVIDs are not checked. Empty or `0` leaves it unset. |
| `token_ttl` | No (default `1h`) | How long an admission is reused before the SVID is verified again; always capped by the SVID's expiry. |
| `entity_kind` | No (default `agent`) | `agent` or `human`: the `kind` fact of every admission. |
| `facts` | No | Map of a built-in field (`spiffe_id`, `trust_domain`, `path`, `svid`, `aud`) to the extra fact name it is published as. At most 32. A write replaces the whole map. |

The native identity is fixed to `spiffe_id`; a write that sets `alias_name_source` is refused. A config write merges onto the stored configuration. A write that carries a key the mount no longer accepts is refused with `400`, naming the key and what replaced it.

### Trust domain (`auth/<mount>/trust-domain/<name>`)

| Field | Required | Description |
|---|---|---|
| `bundle_pem` | For a static X.509-only domain | PEM-encoded X.509 authorities (CA certificates) for the trust domain. |
| `bundle_json` | For JWT-SVID support / `https_spiffe` bootstrap | SPIFFE trust-bundle (JWKS) document; both its X.509 and JWT authorities are used. |
| `bundle_endpoint_url` | For a federated domain | SPIFFE Federation bundle endpoint (`https://`). Setting this makes the domain federated. |
| `bundle_endpoint_profile` | With an endpoint URL | `https_web` (Web PKI) or `https_spiffe` (endpoint authenticated by its own SVID). |
| `endpoint_spiffe_id` | For `https_spiffe` | Expected SPIFFE ID of the bundle endpoint; must be in this trust domain. |
| `web_pki_ca_pem` | No (`https_web` only) | Custom PEM CA roots for the endpoint's TLS certificate (default: system roots). |

A trust domain is either **static** (a `bundle_pem`/`bundle_json` with no `bundle_endpoint_profile`) or **federated** (a `bundle_endpoint_url` plus a `bundle_endpoint_profile`). The three federation fields — `bundle_endpoint_url`, `endpoint_spiffe_id`, and `web_pki_ca_pem` — require a `bundle_endpoint_profile`; setting any of them on a static domain is rejected. Conversely, `endpoint_spiffe_id` is valid only for `https_spiffe`, and `web_pki_ca_pem` only for `https_web`. A write replaces the whole entry and resets its fetch state.

## Troubleshooting

**Gateway request returns `401` with no detail.** This is by design — every admission failure collapses to the same response, so it can't be used to learn which check failed. The Warden server log carries the reason (`implicit authentication failed`: no bundle for the SVID's trust domain, audience mismatch, `max_age`, expired SVID, no bundle loaded, etc.). Check it at the timestamp of the failed call.

**`400` "no role selected".** The request named no role and the provider has no `default_role`. Put the role in the URL (`/v1/<provider>/role/<role>/gateway/...`) or set `X-Warden-Role`.

**Every JWT-SVID is refused, but X.509-SVIDs work.** The mount has no `bound_audiences`, or the JWT-SVIDs are minted for another audience. Set `bound_audiences` on the mount config to the audience your workloads mint their JWT-SVIDs for.

**The config write fails with `bound_audiences is required on agent mounts`.** The write would leave an agent mount without audiences. Send `bound_audiences` in the same write.

**Every request fails right after enabling the method.** A `spiffe` mount admits nothing until at least one trust domain bundle is registered and loaded. Register the trust domain (`auth/<mount>/trust-domain/<name>`) and confirm `warden read` shows a non-zero authority count. If the mount can't load any bundle at startup it fails closed — every SVID is refused until a valid bundle is present.

**`403` `role "inventory-agent" is not assumable through auth/spiffe/: no group grants it to this caller`.** The SVID was admitted, but no group's rule matched its facts. Compare the rule with the SVID's SPIFFE ID: a `*` stops at `/` (use `**` to cross it), `path` starts with `/`, and `trust_domain` must equal the SVID's own domain. Check the rule's `mount` too: it is the path in the mount's namespace, with the trailing slash. The audit entry's `role_denied_reason` and `groups` say which groups matched.

**An SVID is refused even though the certificate looks valid.** The SVID verifies only against the bundle of its own trust domain. Confirm that domain is registered on this mount (`warden list auth/<mount>/trust-domain`), and that its bundle holds the authority that signed the SVID.

**A federated trust domain stopped updating.** Read the trust domain and inspect `last_error` and `last_refresh`. A failed refresh keeps the last-good bundle, so SVIDs keep verifying against the old authorities while refreshes fail in the background. Force a fetch with `auth/<mount>/trust-domain/<name>/refresh`; a `502` there reports the endpoint fetch error directly.

**`https_spiffe` federation won't configure.** The `https_spiffe` profile requires both `endpoint_spiffe_id` (a valid SPIFFE ID inside the trust domain being federated) and a bootstrap bundle (`bundle_json` or `bundle_pem`) that carries X.509 authorities to authenticate the endpoint's SVID on the first fetch. `https_web`, by contrast, rejects `endpoint_spiffe_id` and authenticates the endpoint with ordinary Web PKI.

## See Also

- [Authentication](/identity/authentication/) — how auth mounts admit credentials, and the facts they record.
- [Groups](/identity/groups/) and [Roles](/identity/roles/) — how an admitted workload is granted what it may do.
- [Entities](/identity/entities/) — registering a workload in the identity store.
- [Agent Identity](/agent-identity/) — how a workload or its sidecar presents this credential to Warden.
- [Auth Methods](/auth-methods/) — the other auth methods Warden ships.
