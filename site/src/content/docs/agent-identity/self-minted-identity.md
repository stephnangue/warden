---
title: "Self-Minted SVID — B1"
---

The identity-aware agent **fetches its own SVID from the SPIFFE Workload API and
presents it** to Warden directly. No sidecar sits in the request path. This is
Pattern B — the agent presents its own credential — landing it as a
**self-minted SVID**.

## What it is

The agent links a SPIFFE library and dials the local Workload API
(`$SPIFFE_ENDPOINT_SOCKET`, typically the SPIRE agent's Unix socket). The
Workload API attests the process and hands back its identity — an X.509-SVID or
a JWT-SVID — which the agent presents to Warden: the X.509-SVID by originating
its own mTLS connection, or the JWT-SVID as a bearer header. The SVID is
short-lived and rotates automatically; no key or certificate is written to disk.

> The Workload API issues the SVID; **Warden validates it, never mints it.**
> Warden can source *its own serving certificate* from the Workload API the same
> way, but that is the server side — this page is about the agent presenting its
> identity.

## Request flow

```
   ┌──────────────┐  attest + issue SVID   ┌─────────┐   SVID (mTLS or JWT-SVID)   ┌────────┐
   │ Workload API │ ─────────────────────► │  agent  │ ──────────────────────────► │ Warden │
   │ (SPIRE agent)│   auto-rotating        │         │                             │        │
   └──────────────┘                        └─────────┘                             └────────┘
```

## How Warden authenticates it

The presented SVID — X.509-SVID via the TLS handshake, or JWT-SVID on
`Authorization: Bearer` — is validated by the `spiffe` auth method against the
trust-domain bundles (static or federated). With no `X-Warden-Token`, Warden
uses [transparent authentication](/concepts/authentication/#transparent-authentication)
and resolves the SPIFFE ID to a role per request. SPIFFE relies on short-lived
SVIDs and bundle rotation rather than revocation lists. See
[Authentication](/concepts/authentication/#auth-methods).

## In practice

An autonomous remediation agent written in Go runs in a SPIRE-enabled cluster. At
startup it uses the `go-spiffe` Workload API client to obtain its X.509-SVID, then
opens a mutually-authenticated connection straight to Warden — no sidecar in the
path. The SVID rotates in memory on its own and the agent writes no key to disk.
Warden validates the SVID's SPIFFE ID through the `spiffe` method and maps it to a
role scoped to exactly what the agent may do — for instance, restart a single
named Kubernetes deployment and nothing else.

## When to choose it

- The agent is **identity-aware** and can link a SPIFFE library.
- You run a **SPIFFE/SPIRE** deployment and want keyless, auto-rotating identity
  with **no sidecar** in the request path.
- You want the agent to be able to **reason about its own identity** (e.g. to
  fetch SVIDs for several destinations, not just Warden).

## Trade-offs

- **Application change** — the agent must integrate the Workload API rather than
  speaking plain HTTP to a co-process.
- **Requires a SPIFFE provider** — a SPIRE agent (or equivalent) must run on the
  node and expose the Workload API socket.
- **Strong upside** — no long-lived credential anywhere, automatic rotation, and
  cryptographic, attested per-workload identity.

## See Also

- [Sidecar mTLS Tunnel](/agent-identity/sidecar-tunneled-cert/) — same SPIFFE identity, but a
  sidecar originates the mTLS leg so the agent stays identity-unaware.
- [Platform Token Relay](/agent-identity/platform-issued-token/) — the agent presents identity
  itself here too, but relays a platform token instead of minting an SVID.
- [Authentication](/concepts/authentication/) — transparent auth and the
  `spiffe` method.
