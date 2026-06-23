# Discovery and Skills

For an AI agent, the hard part of using Warden is not making the request — it is
knowing *what it is allowed to do* and *how to do it*. Warden makes both
answerable at runtime. An authenticated agent can ask the server which
[roles](roles.md) it can assume, which [provider](providers.md) mounts exist in
its [namespace](namespaces.md), and how to drive each one — with **no
pre-distributed configuration**. Nothing is hard-coded into the agent; every fact
comes from a live call.

This has two halves:

- **Discovery** — live, identity-scoped introspection of what the caller can
  reach: its roles, its providers, and the API schema.
- **Skills** — agent-facing markdown recipes that teach an agent how to use a
  capability once it has discovered it.

## The Discovery Loop

The seeded `discovery` skill codifies the loop an agent runs before touching any
upstream. Each step returns structured JSON and chains into the next:

1. **Confirm the session** — `WARDEN_ADDR`, `WARDEN_TOKEN` (or
   `WARDEN_CLIENT_CERT`/`WARDEN_CLIENT_KEY`), and `WARDEN_NAMESPACE` are
   pre-populated by the runtime; the agent just checks they are set.
2. **Discover roles** — `warden role list` returns every role the identity can
   assume, each with an operator-written description.
3. **List providers** — `warden provider list` returns the mounts in the
   namespace, each with a `mount_url` and a description.
4. **Match task → provider, pick a role** — the agent reads the descriptions,
   chooses the most-scoped option, and surfaces to the user rather than guessing
   when it is ambiguous.
5. **Read the provider skill and call** — `warden skill read <type>` returns the
   recipe for that provider; the agent follows it to make the request.

Each surface is covered below.

## Discovering Roles

`warden role list` (backed by `sys/introspect/roles`) answers *"which roles can
**I** assume?"* It is identity-scoped: Warden detects the caller's credential
form — a TLS client certificate, a generic JWT, or a Kubernetes ServiceAccount
JWT — and fans out only to the auth mounts in the namespace that accept that
form, returning the **union** of the roles each reports.

```bash
warden role list                       # roles this identity can assume
warden role list -o json               # machine-readable, for agents
warden role list -auth-path auth/jwt/  # restrict to one auth mount
```

Each result carries a `name`, an `auth_path`, and a `description`. A mount that
fails introspection is reported as a warning on stderr; the command still exits
0, so one broken mount cannot hide the rest. The agent never needs role names
distributed out of band — it learns them from its own credential.

## Discovering Providers

`warden provider list` (backed by `sys/providers`) returns the provider mounts in
the caller's namespace. For each it reports the `type`, the operator-set
`description`, and a `mount_url` with the namespace and mount path already baked
in:

```bash
warden provider list -o json
```

The agent reaches the upstream by appending `$WARDEN_ADDR` + `mount_url` + the
per-provider suffix (`gateway`, `role/<role>/gateway`, …). Because `mount_url`
already begins `/v1/<namespace>/<mount>/`, the namespace must **not** be prefixed
again.

> **Identify a mount by its description, not its type or URL.** Several mounts can
> share a provider type — especially the generic [`rest`](providers.md) provider,
> where one mount fronts Stripe and another an internal API. The operator-set
> **description** is the only reliable signal of what a mount is for; the type and
> URL are not. When it is ambiguous, an agent should ask rather than guess.

## Discovering the Schema

`warden schema` (backed by `sys/schema`, with `sys/internal/specs/openapi` as a
Vault-compatible alias) returns an OpenAPI description of the endpoints the
caller can reach. It is namespace-scoped — the document only includes mounts in
the caller's namespace, so one tenant cannot enumerate another's backends.

```bash
warden schema --list           # every reachable path
warden schema aws/config       # describe one path
warden schema aws/config -raw  # raw OpenAPI fragment (for codegen)
```

## Skills

A **skill** is an agent-facing markdown document, stored in a single global
registry, that teaches an agent how to use a capability. Each skill is markdown
with structured frontmatter:

| Field | Meaning |
|-------|---------|
| `name` | Unique slug (for a provider guide, the provider type, e.g. `aws`). |
| `description` | One-line summary an agent reads to decide relevance. |
| `category` | `agent-flow`, `shared`, `provider-guide`, `troubleshooting`, or `custom`. |
| `requires` | Other skills this one depends on (e.g. provider guides require `foundation` and `discovery`). |
| `upstream` | The upstream system the skill is about, when applicable. |
| `provider` | Provider type a `provider-guide` describes. |
| `body` | The markdown recipe itself. |
| `version` | Incremented on every change — agents use it to invalidate caches. |

The `body` is a self-contained recipe: how to build the URL, which headers to
send, and the provider's quirks (an AWS skill notes that an expired JWT surfaces
as a SigV4 `SignatureDoesNotMatch`; a Slack skill notes that HTTP 200 does not
mean success — check the `ok` field).

### Where skills come from

- **Foundation skills** (`foundation`, `discovery`, troubleshooting) are seeded
  into every server on first unseal. They teach the discovery loop itself.
- **Provider skills** ship alongside each provider's code and are seeded into the
  registry the **first time a provider of that type is mounted**. Seeding is
  idempotent: mounting a second instance does not overwrite an operator's edits,
  and a skill that fails to seed never blocks the mount.

So if `warden skill read aws` returns 404, no AWS provider has been enabled on
the server — the honest signal to an agent that the capability does not exist,
rather than an endpoint to fabricate.

### Reading skills

```bash
warden skill list                        # the catalog (bodies omitted)
warden skill list -category=provider-guide
warden skill read discovery              # full record as JSON
warden skill read aws -raw               # just the markdown body
```

The `list` endpoint omits bodies and returns each skill's `version`, so a
long-running agent can cache the catalog and re-fetch only what changed.

### Managing skills

Operators can add custom skills — internal runbooks, house conventions — or
override a seeded one:

```bash
warden skill create -name=oncall-runbook -category=custom \
  -description="on-call response" -body-file=./runbook.md
warden skill update aws -description="our AWS override"
warden skill delete oncall-runbook
```

Reads are open in any namespace; **mutations (`create`/`update`/`delete`) are
restricted to the root namespace** — a sub-namespace request is rejected with
*"skill mutations are restricted to the root namespace."*

## Everything Is Identity-Scoped

Discovery never reveals more than the caller can actually use. Role introspection
returns only roles reachable by the caller's credential type; provider listing
and schema return only mounts in the caller's namespace. An agent's view of the
system *is* its access — which is what lets it self-onboard safely without an
operator hand-feeding it endpoints, role names, or keys.

## See Also

- [Roles](roles.md) — what `warden role list` discovers.
- [Providers](providers.md) — what `warden provider list` discovers, and the
  identify-by-description rule.
- [Authentication](authentication.md) — the credential discovery is scoped to.
- [Namespaces](namespaces.md) — the boundary every discovery surface respects.
