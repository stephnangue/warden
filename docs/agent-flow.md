# Agent end-to-end flow

How an AI agent goes from "I have a task" to "I successfully called an
upstream service through Warden" — every step, every command, every
response shape, and where each piece of knowledge comes from.

This document is for two audiences:

- **Operators** who deployed Warden and connected it to an identity
  issuer (OIDC provider, mTLS CA, …) for agent workloads, and want to
  trace what an agent does end-to-end — from the JWT its runtime
  obtained from that issuer, through the discovery loop, to the
  upstream call.
- **Agent / runtime developers** wiring Warden into Claude Code, Goose,
  or a homegrown harness.

The agent's own copy of this flow lives in the binary as three seeded
skills (`discovery`, `foundation`, `troubleshooting`) served at
`/v1/sys/skills`. This doc is the system-side view of the same contract.

## 1. The runtime contract

The agent does **not** authenticate against an identity provider, fetch
tokens, or hard-code endpoints. The runtime that spawns the agent
populates four environment variables before the agent process starts:

| Env var | Purpose | Set by |
|---|---|---|
| `WARDEN_TOKEN` | A JWT bearer token. | Runtime (e.g. CI's per-job OIDC token, an OAuth client_credentials JWT minted at agent spawn). |
| `WARDEN_ADDR` | Warden server URL. | Runtime (one Warden cluster per environment). |
| `WARDEN_NAMESPACE` | Namespace to scope every call to. | Runtime (per-tenant or per-team). |
| `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY` | (Alternative to `WARDEN_TOKEN`) PEM paths for mTLS. | Runtime (only when the deployment uses cert-based identity). |

That's the whole onboarding ceremony. The agent inherits credentials
from the environment and never sees an upstream API key.

## 2. The bootstrap prompt

The runtime injects **one sentence** into the agent's system prompt:

> *"To learn how to operate on Warden, run `warden skill read discovery --raw`. Use `warden skill list -F name,description` to browse the catalog of available skills."*

Everything else — the discovery loop, the env-var conventions, the
provider recipes — the agent learns by reading skills at runtime. No
hard-coded knowledge, no pre-loaded context, no SDK to keep in sync
with the server.

This is the **chicken-and-egg shortcut**: a one-liner that points at
`discovery`, which then expands into the full flow. The discovery skill
is seeded into every Warden cluster at first unseal, so it's always
available — there is no "is the skill there?" check the agent has to do
itself.

## 3. The five-step discovery loop

The `discovery` skill (served from `/v1/sys/skills/discovery`)
codifies the loop the agent runs **before every request to an upstream
service**. Every step returns structured JSON; the agent chains them
deterministically.

### Step 1 — Confirm the session

The agent reads the four env vars and aborts (with a clear message to
the user) if `WARDEN_NAMESPACE` is missing. Calling the root namespace
with no scoping is almost always an operator-setup bug — better to
surface than silently call the wrong scope.

### Step 2 — Discover assumable roles

```bash
warden role list -o json -F name,description
```

Hits `GET /v1/sys/introspect/roles`. The endpoint introspects the
caller's identity vehicle (JWT or client cert) and returns the roles
that identity can assume in the current namespace. The wire payload
also carries an `auth_path` (which auth mount granted the role —
operator-facing metadata for debugging); the `-F name,description`
projection drops it because the agent decides by description alone.

```json
[
  {"name": "data-reader",      "description": "Read-only access to data warehouses"},
  {"name": "deploy-bot",       "description": "Deploy via TFE; full access to staging"},
  {"name": "vault-secrets-ro", "description": "Read app-config secrets from Vault"}
]
```

Each `description` is **operator-set free text**. It's how operators
communicate intent to agents at runtime. The agent reads descriptions
and matches them to the task — it does not memorize role names.

### Step 3 — List providers in this namespace

```bash
warden provider list -o json -F type,description,mount_url
```

Hits `GET /v1/sys/providers?warden-list=true`. The wire payload also
carries `path` (the bare mount slug like `aws/`) and `accessor` (a
server-internal opaque ID); the projection drops both because the
agent has everything it needs in `mount_url`. Three fields the agent
keeps:

- `type` — the lookup key for the matching provider skill.
- `description` — what the agent matches the task against.
- `mount_url` — the relative URL path with namespace + mount baked in.
  The agent appends `$WARDEN_ADDR` plus the per-provider suffix (e.g.
  `gateway`, `role/<role>/gateway`, `access/<grant>`) from the
  provider's skill to construct the upstream URL. No string surgery
  on `$WARDEN_NAMESPACE`.

```json
[
  {"type": "aws",    "description": "Production AWS account 1234",     "mount_url": "/v1/team-data/aws/"},
  {"type": "openai", "description": "OpenAI API for embeddings + chat", "mount_url": "/v1/team-data/openai/"},
  {"type": "rds",    "description": "RDS PostgreSQL — analytics",      "mount_url": "/v1/team-data/rds-pg/"},
  {"type": "vault",  "description": "Internal Vault — secrets/, pki/", "mount_url": "/v1/team-data/vault/"}
]
```

If the list is empty or returns `forbidden`, that's an operator-setup
problem — the agent surfaces it, doesn't paper over with a hard-coded
URL.

### Step 4 — Match task → provider, pick a role

Read role and provider descriptions side-by-side. Most fits are obvious:

> *"Read S3 bucket analytics-events"* →
> provider `aws/` (description: AWS) +
> role `data-reader` (description: read-only data warehouses).

When ambiguous (multi-tenant, regional, prod-vs-staging):
- Prefer the **most-scoped** option (a role described as "read-only X"
  over "admin").
- If two providers look equivalent, surface to the user rather than
  guess.

### Step 5 — Read the provider skill, call the provider

```bash
warden skill read <type> --raw
```

Hits `GET /v1/sys/skills/<type>`. Returns the agent-facing recipe in
markdown — endpoint URL, required env vars, role-selection mechanic,
copy-paste examples.

If `warden skill read aws` returns 404, the cluster does not have an AWS
provider configured (provider skills are seeded into the registry the
first time a provider of that type is mounted). The agent surfaces the
gap, doesn't fabricate a SigV4 endpoint.

## 4. Worked example — read an S3 bucket through AWS

The runtime spawns the agent with:

```
WARDEN_TOKEN=eyJhbGc…   # OIDC JWT from CI
WARDEN_ADDR=https://warden.example.com
WARDEN_NAMESPACE=team-data
```

User asks: *"Show me the keys in the staging-events S3 bucket."*

**Agent's actions:**

1. **Session check** — env vars present. ✓
2. **`warden role list -o json -F name,description`** — finds `data-reader` ("Read-only access to data warehouses").
3. **`warden provider list -o json -F type,description,mount_url`** — finds an `aws` provider ("Production AWS account 1234", `mount_url=/v1/team-data/aws/`) plus an unrelated `openai`.
4. **Match** — `data-reader` + `aws/` fit the task. No ambiguity.
5. **`warden skill read aws --raw`** — gets the recipe:

   ```bash
   export AWS_ACCESS_KEY_ID="<role-name>"
   export AWS_SECRET_ACCESS_KEY="$WARDEN_TOKEN"
   export AWS_SESSION_TOKEN="$WARDEN_TOKEN"
   export AWS_ENDPOINT_URL="$WARDEN_ADDR<mount-url>gateway"
   ```

6. **Substitute and run** (using `mount_url=/v1/team-data/aws/` from step 3):

   ```bash
   export AWS_ACCESS_KEY_ID=data-reader
   export AWS_SECRET_ACCESS_KEY=$WARDEN_TOKEN
   export AWS_SESSION_TOKEN=$WARDEN_TOKEN
   export AWS_ENDPOINT_URL=https://warden.example.com/v1/team-data/aws/gateway
   aws s3 ls s3://staging-events
   ```

The SDK signs the request with SigV4 as usual. Warden's AWS provider
verifies the signature, reads the role name out of the
`AWS_ACCESS_KEY_ID` slot, looks up the credential spec bound to that
role, mints fresh AWS credentials, re-signs the request, and proxies to
`s3.amazonaws.com`. The response streams back through Warden to the
agent. The real AWS credentials never leave Warden's process; the SDK
never sees them.

## 5. What changes per provider type

Step 1–4 of the discovery loop are universal. Step 5's recipe varies
by provider type. The skill registry surfaces the exact recipe for
each type:

| Provider type | Recipe shape | How role is passed |
|---|---|---|
| `aws`, `scaleway` | SDK env vars (`AWS_ACCESS_KEY_ID` carries the role name, JWT in the secret/session slot, endpoint pointed at the gateway). | Role embedded in `AWS_ACCESS_KEY_ID` (extracted by Warden from the SigV4 header). |
| `openai`, `anthropic`, `github`, etc. | API key replaced with the JWT; base URL pointed at `<mount_url>role/<role>/gateway`. | URL path segment: `…/role/<role>/gateway/…`. |
| `vault` | API call to `<mount_url>role/<role>/gateway/v1/<vault-path>` with `X-Vault-Token: $WARDEN_TOKEN`. | URL path segment, same as the other HTTP gateways. |
| `rds` | One-shot API call to mint a short-lived JDBC/PSQL connection string with an embedded IAM auth token; the agent then connects directly to the DB (no proxy in the data path). | Query parameter: `…/access/<grant>?role=<role>` (access backends, not gateways, so role lives in the query string). |

The skill body for each type explains the exact substitution, the quirks
(e.g. AWS wildcard DNS for S3 virtual-hosted buckets, JWT-expiry
manifesting as SigV4 `SignatureDoesNotMatch`), and any service-specific
caveats.

## 6. Error handling

The `troubleshooting` skill (`/v1/sys/skills/troubleshooting`) maps
every CLI exit code to a category, a likely cause, and a retry policy:

| Exit | Code | When the agent should… |
|---|---|---|
| 4 | `auth_required` | Refresh the JWT (typical TTL is 5–60 min) and retry. |
| 5 | `forbidden` | Re-run `warden role list` and pick a different role; if no role fits, surface to the user — don't escalate. |
| 6 | `not_found` | Re-run `warden provider list` / `warden role list`; the operator may have changed the namespace's mounts. |
| 3 | `invalid_input` | Read the error envelope's `message` (validators emit one line per problem with "did you mean" hints) and fix the payload. |
| 7 | `network` | Backoff + retry. For SigV4 providers, also check wildcard DNS. |
| 8 | `server` | Read the upstream error verbatim — Warden surfaces it. Bounded retry on transient upstream errors. |
| 9 | `conflict` | Resource exists. Read it and update, or pick a different name. Don't retry blindly. |

The structured `code` field is the contract — agents branch on it, never
on the human-readable message.

## 7. Caching strategy

Skills change rarely; agents can cache them. Every skill record carries
a `version` integer bumped on every update. A long-running agent can:

1. Cache `discovery`, `foundation`, `troubleshooting`, and the
   provider skills it has read.
2. On subsequent reads, fetch the LIST endpoint (one cheap call,
   no bodies) and compare each cached skill's `version` with the
   server's. Re-fetch only the records whose version changed.

Roles and providers are also stable-ish — re-discover every N minutes
or on a `not_found` / `forbidden` error, whichever comes first.

## 8. The big picture

### Setup — one-time, by the operator

```
┌─────────────────────────┐                ┌─────────────────────────┐
│ Identity issuer         │ ◄─── trust ──► │ Warden cluster          │
│ (OIDC, mTLS CA, SPIRE…) │                │  • providers mounted    │
└─────────────────────────┘                │  • roles + policy       │
                                           │  • skill catalog seeded │
                                           └─────────────────────────┘
```

The operator configures the trust relationship between the issuer and
Warden (JWKS endpoint or CA bundle), then mounts providers, defines
roles, and writes policies. After this, the operator is not in the
per-call loop.

### Per-call — every time an agent makes an upstream call

```
        ┌──────────────────────┐
        │ Identity issuer      │
        └─────────┬────────────┘
                  │ ① mint JWT (per job, per spawn, …)
                  ▼
        ┌──────────────────────┐
        │ Runtime              │   sets WARDEN_TOKEN, WARDEN_ADDR,
        │ (CI, harness, …)     │        WARDEN_NAMESPACE; injects
        └─────────┬────────────┘        the bootstrap system prompt
                  │ ② spawn
                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Agent                                                               │
│                                                                     │
│  ③ Discovery loop — each step is a GET, response is structured JSON │
│       foundation, discovery, role list, provider list, match,       │
│       provider skill         (all under /v1/sys/...)                │
│                                                                     │
│  ④ Upstream call    POST /v1/<mount>/gateway/...                    │
│                     Authorization: Bearer $WARDEN_TOKEN             │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Warden                                                              │
│   ⑤ auth      validate the JWT against the issuer's JWKS / CA       │
│   ⑥ policy    resolve role; check namespace + policy permit the call│
│   ⑦ credmint  mint a short-lived real upstream credential           │
│   ⑧ proxy     re-sign / inject the credential; forward to upstream  │
└─────────────────────────────────┬───────────────────────────────────┘
                                  │ ⑨ call with real upstream creds
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Upstream (AWS, OpenAI, Vault, RDS, GitHub, …)                       │
│   sees: a normal call from Warden with valid real credentials       │
│   does NOT see: the agent's JWT, the agent's namespace, role name   │
└─────────────────────────────────────────────────────────────────────┘
```

Responses flow back along the same path. Warden does not cache real
upstream credentials in storage — they're minted per call (or
short-lived, per the credential spec's TTL) and held only in memory
for the duration of the proxied request.

## 9. What the agent never does

- **Authenticate to an identity provider.** The runtime hands it a JWT.
- **Hold long-lived upstream credentials.** Warden mints them per call.
- **Memorize role names, provider paths, or endpoint URLs.** Every fact
  comes from a live introspection call or a skill record.
- **Decide on its own that "the system is broken."** A 4xx/5xx with a
  structured `code` field maps deterministically to an action (retry,
  pick another role, surface to the user). Ambiguous failures get
  surfaced, not papered over.

## 10. Where to go next

- The seeded skills themselves — `warden skill list`, `warden skill read <name> --raw` — are the authoritative agent-facing source. This doc is the system view of the same contract.
- For a worked tutorial that wires Goose into Warden against three upstreams in parallel, see [tutorials/vault-policy-hygiene/](tutorials/vault-policy-hygiene/).
- For the proxy/gateway internals (how Warden re-signs SigV4, validates JWTs against the OIDC issuer, etc.), see [architecture.md](architecture.md).
- For the per-provider catalog (what each type supports and how it's configured), see [providers.md](providers.md).
