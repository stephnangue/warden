# Sidecar Token Injection (Robin) — A1

A sidecar holds the workload's identity token and **adds it to each request**.
The agent sends a plain HTTP request to the sidecar on loopback and stays
identity-unaware; the sidecar attaches `Authorization: Bearer <token>` and
forwards the call to Warden. This is Pattern A — a co-process presents the
identity — landing it as an **injected token**.

## What it is

[Robin](https://github.com/stephnangue/robin) runs beside the agent, holds the
workload's identity token — an OIDC JWT, a JWT-SVID, or a projected Kubernetes
ServiceAccount token — and attaches it as a bearer header on every request to
Warden. The application is wired to call
`http://127.0.0.1:<port>` instead of Warden directly; it carries no Warden
secret and needs no knowledge of how it is authenticated.

## Request flow

```
┌─────────┐  plain HTTP   ┌──────────┐  + Authorization: Bearer <jwt>    ┌────────┐
│  agent  │ ────────────► │  Robin   │ ────────────────────────────────► │ Warden │
│         │   (loopback)  │ sidecar  │             (over TLS)            │        │
└─────────┘               └──────────┘                                   └────────┘
                          holds the JWT /
                          JWT-SVID identity
```

## How Warden authenticates it

The injected bearer token is validated by the auth method that matches its
issuer: the `jwt` method (against an OIDC discovery URL, JWKS, or static keys);
the `kubernetes` method, for a projected ServiceAccount token, via the cluster's
TokenReview API; or the `spiffe` method, for a JWT-SVID, against the
trust-domain bundles. Because the request arrives with no
`X-Warden-Token`, Warden uses [transparent authentication](../concepts/authentication.md#transparent-authentication):
it logs the caller in against the provider's configured auth mount, resolves the
role, and caches the result — no Warden session token is ever returned to the
agent. The auth-method and role mechanics are in
[Authentication](../concepts/authentication.md#auth-methods).

## In practice

A LangChain agent runs as a pod in a Kubernetes cluster and needs the Anthropic
API. Kubernetes projects a ServiceAccount token into the pod; a **Robin** sidecar
in the same pod reads it and attaches it as `Authorization: Bearer` on every
call. The agent is configured with `ANTHROPIC_BASE_URL=http://127.0.0.1:8080` —
as far as it knows, it is talking to the Anthropic API directly. Robin forwards
to Warden, which validates the ServiceAccount token through the `kubernetes`
method, injects the real Anthropic key, and proxies the request. The agent image
holds no API key and no Warden token, and rotating the upstream key changes
nothing in the pod.

## When to choose it

- The credential is a **bearer token**, not a certificate.
- You want the application **unchanged** — it speaks plain HTTP and knows nothing
  about identity.
- Especially strong on **Kubernetes**: each pod already has a ServiceAccount
  identity, so Robin can present a per-pod JWT to Warden without baking a
  long-lived secret into the image or manifest.

## Trade-offs

- **Runs a co-process** — one more container/process to deploy and watch.
- **The agent stays identity-unaware** — nothing to change in application code,
  but also nothing the application can reason about regarding its own identity.
- **Bearer-token blast radius** — a leaked bearer token is replayable until it
  expires; favour short-lived, frequently-rotated tokens.
- **Loopback trust** — anything that can reach the sidecar's loopback port speaks
  as the workload, so the sidecar and app must share a trust boundary (e.g. the
  same pod).

## See Also

- [Sidecar mTLS Tunnel](sidecar-tunneled-cert.md) — the certificate sibling, when
  identity is an X.509/SVID rather than a bearer token.
- [Platform Token Relay](platform-issued-token.md) — the same token, presented by
  the agent itself instead of a sidecar.
- [Authentication](../concepts/authentication.md) — transparent auth and the
  `jwt` / `kubernetes` / `spiffe` methods.
