---
title: "Sidecar mTLS Tunnel (ghostunnel) — A2"
---

A sidecar **terminates the agent's plaintext locally and carries identity in an
mTLS channel** to Warden. The agent sends a plain HTTP request on loopback; the
sidecar holds the client certificate, originates the mutually-authenticated TLS
leg, and forwards the request. This is Pattern A — a co-process presents the
identity — landing it as an **mTLS tunnel**.

## What it is

[ghostunnel](https://github.com/ghostunnel/ghostunnel) runs beside the agent,
holds the workload's client certificate and key (or an X.509-SVID), and
originates the client-authenticated TLS connection to Warden, forwarding
plaintext from the local application. The identity rides the TLS handshake
itself — the request body carries no credential header at all.

> **mTLS is a property of the connection, not of any one client.** A certificate
> authenticates because it is presented during the TLS handshake — *any* client
> that completes a client-authenticated handshake works. ghostunnel is simply the
> process that completes it on the workload's behalf.

## Request flow

```
┌─────────┐  plain HTTP   ┌────────────┐   mTLS (client cert / X.509-SVID)   ┌────────┐
│  agent  │ ────────────► │ ghostunnel │ ──────────────────────────────────► │ Warden │
│         │   (loopback)  │  sidecar   │       identity in the TLS leg       │        │
└─────────┘               └────────────┘                                     └────────┘
                          holds the cert/key
```

## How Warden authenticates it

The client certificate from the handshake is validated by the `cert` auth
method (chain-of-trust against the configured CA bundle) or, for an X.509-SVID,
the `spiffe` method against the trust-domain bundles. With no `X-Warden-Token`
on the request, Warden uses [transparent authentication](/concepts/authentication/#transparent-authentication)
and resolves the identity from the certificate per request. The identity can
equally arrive on a forwarded header (`X-Forwarded-Client-Cert`) when Warden
sits behind a TLS-terminating proxy. mTLS requires a Warden listener configured
to request client certificates — see [Authentication](/concepts/authentication/#auth-methods).

## In practice

**Claude Code** runs on a developer's workstation, where you cannot mint a bearer
token without holding a static credential to mint it from — so identity is a
keyless SPIFFE X.509-SVID instead, attested and delivered by SPIRE. Claude Code
routes its model calls to whatever endpoint `ANTHROPIC_BASE_URL` names, but it
cannot originate a TLS client handshake itself. A local **ghostunnel** process
holds the workstation's SPIRE-issued X.509-SVID, listens on loopback, and
originates the mTLS leg to Warden; `ANTHROPIC_BASE_URL` points at that local
ghostunnel listener and Claude Code is otherwise untouched. Its model calls go
through Warden, which validates the SVID through the `spiffe` method, injects the
real Anthropic Console key
server-side, and proxies the request. No certificate handling — issuance,
rotation, or the handshake — ever enters the agent. This is exactly the
[SPIFFE workstation quickstart](/quickstarts/workstation/03-spiffe-llm-mcp/).

## When to choose it

- Identity is a **certificate or X.509-SVID** rather than a bearer token.
- You want the application **unchanged** — it speaks plain HTTP on loopback.
- You want **channel-bound** identity: the credential is never a replayable
  header, it is tied to the live TLS connection.

## Trade-offs

- **Runs a co-process** — one more container/process to deploy and watch.
- **Needs an mTLS-capable listener** — does nothing against a plain-HTTP dev
  listener; the deployment must terminate client-authenticated TLS at Warden or a
  trusted proxy.
- **Certificate lifecycle** — cert/key issuance and rotation must be handled
  (SPIRE-issued X.509-SVIDs rotate automatically; static certs do not).
- **Loopback trust** — anything that can reach the sidecar's loopback port is
  tunnelled as the workload, so sidecar and app must share a trust boundary.

## See Also

- [Sidecar Token Injection](/agent-identity/sidecar-injected-token/) — the bearer-token sibling,
  when identity is a JWT rather than a certificate.
- [Self-Minted SVID](/agent-identity/self-minted-identity/) — the agent fetches and presents the
  SVID itself instead of letting a sidecar originate the tunnel.
- [Authentication](/concepts/authentication/) — transparent auth, mTLS, and the
  `cert` / `spiffe` methods.
