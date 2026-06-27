# Authentication

Every request to Warden must carry a credential that identifies the caller.
Authentication is the process of turning that credential into an **identity** —
a set of policies, a namespace, and an expiry — that Warden can authorize. No
identity, no access: an unauthenticated request reaches nothing.

Warden accepts three credential forms and supports two distinct authentication
styles built on top of them. This document explains both, how the CLI and API
client choose what to send, and how an authenticated identity becomes an
authorization decision.

## Credentials

A caller authenticates by presenting one of three credentials:

| Credential | How it is sent | Typical holder |
|------------|----------------|----------------|
| **Warden token** | `X-Warden-Token` header | a human operator, a script, the root token |
| **Bearer JWT** | `Authorization: Bearer <jwt>` header | a workload with an OIDC/Kubernetes/SPIFFE JWT |
| **mTLS client certificate** | the TLS handshake | a workload with an X.509 identity, often via a sidecar |

The credential you hold determines which authentication style applies, described
next.

> **mTLS is a property of the connection, not of any one client.** A client
> certificate authenticates because it is presented during the TLS handshake —
> *any* TLS client that completes a client-authenticated handshake works.
> A sidecar can present the credential for the workload:
> **[ghostunnel](https://github.com/ghostunnel/ghostunnel)** holds a
> client certificate and originates the mTLS leg, while
> [Robin](https://github.com/stephnangue/robin) channels a bearer JWT instead.
> Such a sidecar authenticates to Warden without using the Warden CLI or its
> `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY` variables at all; those variables
> are simply how the Warden CLI loads a certificate when *it* is the client. The
> identity can equally arrive on a forwarded header (`X-Forwarded-Client-Cert`)
> when Warden sits behind a TLS-terminating proxy. Either way, mTLS requires a
> listener configured to request client certificates — it does nothing against
> the plain-HTTP [dev server](dev-server.md) listener.

## Two Styles of Authentication

### Explicit authentication

You authenticate **explicitly** by logging in. A caller presents a credential to
an auth method, Warden issues a **session token** (a Warden token), and the caller
sends it on the `X-Warden-Token` header with every subsequent request. Warden
looks the token up, checks that it has not expired and belongs to the request's
namespace, and uses the policies attached to it. (A fresh dev or production server
starts with the root token.)

This is the familiar Vault-style flow: authenticate once, carry a token.

### Transparent authentication

AI agents and workloads need to talk to Warden **as if it were the upstream
system** — the LLM API, the database, the Git server they were already built to
call. They should not have to learn a Warden-specific login handshake or carry a
Warden-specific token; they should just point their existing client at Warden
and present the credential they already hold. That is why Warden supports
**transparent authentication**.

When a request arrives with **no** `X-Warden-Token`, Warden authenticates it
*directly* from the JWT or mTLS certificate it carries — the same SPIFFE SVID,
OIDC token, or client certificate the workload already uses for the mesh —
logging in on the caller's behalf against a pre-configured auth mount and caching
the resulting token. Identity is resolved per request, with no separate login
step, so a client built for the upstream works against Warden unchanged.

The workload need not even manage that credential itself: a **sidecar** can hold
the identity and present it to Warden, so the application carries no secret and
speaks plain HTTP on loopback. This is the common deployment shape for agents and
workloads — see [Channelling Identity with a Sidecar](#channelling-identity-with-a-sidecar).

> **The gate:** the presence of an `X-Warden-Token` header decides the path. If
> it is set, Warden does an explicit token lookup and **skips transparent auth
> entirely**. If it is empty, Warden falls back to the JWT or certificate and
> attempts implicit auth. A JWT is not a Warden session token — it would fail a
> token-store lookup — which is exactly why the CLI routes it through the
> `Authorization` header instead (see [CLI and Client Behavior](#cli-and-client-behavior)).

## Channelling Identity with a Sidecar

A workload rarely attaches its own credential. A **sidecar** runs alongside it,
holds the identity, and presents it to Warden — so the application carries no
secret and speaks plain HTTP to the sidecar over loopback. Two open-source
sidecars cover the two transparent credential forms.

**[Robin](https://github.com/stephnangue/robin) — bearer JWT.** Robin channels a
**JWT**: it holds the workload's identity token and attaches it as
`Authorization: Bearer` on each request to Warden, so the workload authenticates
as itself with nothing wired into the application. It is especially useful in
**Kubernetes**, where each pod already has a ServiceAccount identity that Robin
can present as the workload's JWT — giving every workload a per-pod identity to
Warden without baking a long-lived secret into the image or manifest.

**[ghostunnel](https://github.com/ghostunnel/ghostunnel) — mTLS certificate.** ghostunnel channels an **X.509 identity**: it
holds the workload's client certificate and key, originates the
client-authenticated TLS leg to Warden, and forwards plaintext from the local
application. Reach for it where identity is a certificate or SPIFFE SVID rather
than a bearer token.

Either way the workload holds no Warden-specific secret; Warden authenticates the
presented JWT or certificate through [transparent authentication](#transparent-authentication).

For the full set of identity-presentation approaches — sidecar-presented and
agent-presented, and how to choose between them — see
[Agent Identity](../agent-identity/README.md).

## Warden Tokens

A Warden session token is an opaque string with the prefix `cws.` followed by 64
random characters (68 characters total). Warden never stores the raw token; it
stores a hash, and token records are keyed by an internal ID prefixed `wtkn_`.

Each token record binds:

- the **policies** granted to the caller,
- the **namespace** the token was issued in — it is valid there and in any
  descendant (sub-)namespace, but not in a sibling or ancestor namespace,
- an **expiry**, after which the token is rejected. Session tokens default to a
  **1-hour TTL**.

### The root token

The **root token** is a fully-privileged token created when a server is
initialized. On a [dev server](dev-server.md) it is printed in the startup
banner (and can be pinned with `-dev-root-token`); on a production server it is
returned by `warden operator init`. Use it to perform initial setup — enabling
auth methods, writing policies — and prefer narrower credentials for everyday
work.

## Auth Methods

Like Vault, Warden authentication is pluggable. An **auth method** is a backend
you mount under a path; callers log in against it, and it validates their
credential and issues a token with a set of policies. Enable one with:

```bash
warden auth enable cert
```

Warden ships these auth methods; each links to its setup guide under
[Auth Methods](../auth-methods/README.md):

| Method | Type | Validates |
|--------|------|-----------|
| [**Certificate**](../auth-methods/cert.md) | `cert` | an X.509 client certificate against configured rules |
| [**JWT / OIDC**](../auth-methods/jwt.md) | `jwt` | a signed JWT against an OIDC discovery URL, JWKS URL, or static public keys |
| [**Kubernetes**](../auth-methods/kubernetes.md) | `kubernetes` | a Kubernetes ServiceAccount token via the cluster's TokenReview API |
| [**SPIFFE**](../auth-methods/spiffe.md) | `spiffe` | a SPIFFE identity — accepts **either** an X.509-SVID or a JWT-SVID |

### Roles

An auth method is configured with **roles**. A role maps the validated
credential — a certificate fingerprint, a set of JWT claims, a SPIFFE ID — to
the policies and token settings a caller should receive. When a caller logs in,
they select a role (or fall back to the method's `default_role`), and the role
determines what the issued token can do.

### Explicit login vs. transparent roles

A role's `token_type` decides which authentication style it serves:

- A normal role issues a **session token** on login, which the caller then sends
  on `X-Warden-Token`.
- A role with `token_type=transparent` is for implicit auth only. Explicit login
  against it is rejected — *"explicit login is not supported for roles with
  token_type=transparent; clients authenticate implicitly via gateway
  requests"* — because such callers authenticate per request from their JWT or
  certificate.

### Where transparent auth looks

For an implicit request, Warden needs to know which auth mount to log the caller
in against. That target — the **auto-auth path** — comes from configuration, not
from the request:

- **Gateway / proxy requests** use the provider's `auto_auth_path`.
- **Operational requests** use the namespace's `auto_auth_path` metadata.

Warden resolves the mount at that path, confirms it is a transparent-capable
auth method, extracts the credential the method expects (a client certificate or
a bearer JWT), and resolves the role from — in order — the `X-Warden-Role`
header, the role encoded in the request, a provider-supplied default, or the
auth method's `default_role`. Identical credential-plus-role combinations are
deduplicated and the resulting token is cached, so a busy workload does not
trigger a fresh login on every call.

## CLI and Client Behavior

The CLI and API client read their configuration from `WARDEN_`-prefixed
environment variables and decide which credential to present:

- **`WARDEN_TOKEN`** is sent on the `X-Warden-Token` header — *unless* the value
  looks like a JWT. If the token begins with `eyJ` (the base64 of `{"`, the
  start of every JWT header), the CLI moves it to `Authorization: Bearer <jwt>`
  and clears `X-Warden-Token`, so the server's transparent-auth gate engages and
  resolves it via implicit auth.
- **`WARDEN_CLIENT_CERT`** and **`WARDEN_CLIENT_KEY`** load an X.509 client
  certificate into the TLS config for mTLS. Both must be set together.
- **`WARDEN_CACERT`** / **`WARDEN_CAPATH`** trust the server's certificate;
  **`WARDEN_TLS_SERVER_NAME`** and **`WARDEN_SKIP_VERIFY`** tune verification.
- **`WARDEN_NAMESPACE`** and **`WARDEN_ROLE`** set the `X-Warden-Namespace` and
  `X-Warden-Role` headers.

### Environment variable reference

| Variable | Purpose |
|----------|---------|
| `WARDEN_ADDR` | Server address, e.g. `http://127.0.0.1:8400`. |
| `WARDEN_TOKEN` | Warden token or JWT used to authenticate the request. |
| `WARDEN_CLIENT_CERT` | Client certificate file for mTLS authentication. |
| `WARDEN_CLIENT_KEY` | Private key matching `WARDEN_CLIENT_CERT`. |
| `WARDEN_CACERT` | CA certificate file used to verify the server. |
| `WARDEN_CAPATH` | Directory of CA certificates used to verify the server. |
| `WARDEN_TLS_SERVER_NAME` | Server name to use for TLS verification (SNI). |
| `WARDEN_SKIP_VERIFY` | Disable TLS verification (insecure; dev only). |
| `WARDEN_NAMESPACE` | Namespace for the request (`X-Warden-Namespace` header). |
| `WARDEN_ROLE` | Role for transparent auth (`X-Warden-Role` header). |

## From Identity to Authorization

Authentication establishes *who* the caller is; **authorization** decides what
they may do. Once Warden resolves an identity — by token lookup or implicit
login — it has the caller's namespace and the set of policies attached to their
token, and it evaluates the request against those policies. Namespace access is
hierarchical: a token issued in a parent namespace is also valid in its
descendant namespaces, but never in a sibling or ancestor namespace.

Policy evaluation itself is covered in [Policies](policies.md); [Namespaces](namespaces.md)
covers the isolation boundary, and the [Architecture](../architecture.md) overview
shows how the pieces fit together.

## Troubleshooting

When a request is rejected for missing or invalid credentials, the CLI prints:

```
Set WARDEN_TOKEN, configure WARDEN_CLIENT_CERT/WARDEN_CLIENT_KEY for mTLS, or pass an Authorization: Bearer JWT
```

Common causes:

- **No credential presented.** Set `WARDEN_TOKEN`, or configure
  `WARDEN_CLIENT_CERT` / `WARDEN_CLIENT_KEY`, or send a Bearer JWT.
- **Expired token.** Session tokens default to a 1-hour TTL; log in again.
- **Wrong namespace.** A token is valid in its own namespace and any descendant,
  but not in a sibling or ancestor namespace. Check `WARDEN_NAMESPACE`.
- **Explicit login against a transparent role.** Such roles only accept implicit
  auth; send the credential on the request itself rather than calling login.
- **JWT sent as a Warden token.** A raw JWT on `X-Warden-Token` fails token
  lookup. The CLI converts `eyJ…` tokens automatically; if you build requests
  yourself, send the JWT on `Authorization: Bearer`.
