# Platform Token Relay — B2

The identity-aware agent **forwards a token its platform already issued** —
a projected Kubernetes ServiceAccount token, a CI system's OIDC token — to
Warden directly. No sidecar sits in the request path, and the agent does not
mint identity of its own; it relays the platform's. This is Pattern B — the
agent presents its own credential — landing it as a **relayed platform token**.

## What it is

The runtime hands the agent a token that already attests who it is: Kubernetes
projects a ServiceAccount token into the pod, a CI runner exposes an OIDC token
for the job. The agent reads that token and attaches it as
`Authorization: Bearer <token>` on its requests to Warden. It did not create the
identity — the platform did — it simply relays it.

## Request flow

```
┌────────────────┐  issues token   ┌─────────┐   Authorization: Bearer <token>   ┌────────┐
│   platform     │ ──────────────► │  agent  │ ────────────────────────────────► │ Warden │
│ (K8s SA / CI)  │  projected SA   │         │                                   │        │
└────────────────┘  token, OIDC    └─────────┘                                   └────────┘
```

## How Warden authenticates it

The relayed token is validated by the auth method that matches its issuer: the
`kubernetes` method verifies a ServiceAccount token via the cluster's
TokenReview API; the `jwt` method verifies a CI OIDC token against the
provider's discovery URL or JWKS. With no `X-Warden-Token` on the request,
Warden uses [transparent authentication](../concepts/authentication.md#transparent-authentication)
to resolve the token to a role per request and caches the result. See
[Authentication](../concepts/authentication.md#auth-methods).

## In practice

A headless AI agent runs as a job in a GitHub Actions workflow — an autonomous
release agent that promotes builds and needs short-lived AWS access to do it. The
runner exposes a per-job OIDC token; the agent fetches it (via
`ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`) and attaches
it to its requests to Warden as `Authorization: Bearer`. Warden validates the
token through the `jwt` method against GitHub's OIDC issuer, checks the repository
and branch claims via the role, mints short-lived AWS credentials, and proxies the
calls. No long-lived AWS keys ever live in the repository's secrets, and the
identity is scoped to the exact workflow run.

## When to choose it

- The agent **already runs on a platform that issues an identity token** —
  Kubernetes, a CI/CD system — and you would rather use that than introduce
  SPIFFE or a sidecar.
- The agent is **identity-aware** enough to read the projected token and set a
  header, but you want **no co-process** in the request path.
- You want identity that the platform **rotates and scopes** for you (projected
  SA tokens are short-lived and audience-bound).

## Trade-offs

- **Application change** — the agent must locate and attach the platform token
  (read the projected file, call the CI token endpoint).
- **Tied to the platform** — the identity is only as good as the issuer; moving
  off Kubernetes/CI means changing how identity is obtained.
- **Bearer-token blast radius** — like any bearer token it is replayable until it
  expires, so prefer short-lived, audience-restricted tokens.

## See Also

- [Sidecar Token Injection](sidecar-injected-token.md) — the same kind of token,
  attached by a sidecar so the agent stays identity-unaware.
- [Self-Minted SVID](self-minted-identity.md) — the agent presents its own
  credential here too, but mints a SPIFFE SVID instead of relaying a platform
  token.
- [Authentication](../concepts/authentication.md) — transparent auth and the
  `kubernetes` / `jwt` methods.
