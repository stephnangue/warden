# Agent Identity

Before Warden can broker access for an agent, it has to know *who the agent is*.
The agent presents an **identity vehicle** — a JWT, a SPIFFE SVID, a client
certificate, a platform-issued token — and Warden validates it, attaches the
resulting principal to the policy decision and the audit trail, and mints the
upstream credential on the agent's behalf. Warden never issues or mints the
agent's own identity; it only consumes one the agent (or its platform) already
holds.

This section is about the **shape of that presentation**: who attaches the
credential, and how it reaches Warden. The validation mechanics — the auth
methods, transparent vs. explicit authentication, roles — live in
[Authentication](../concepts/authentication.md); this section sits on top of
them and helps you choose an approach.

## Two questions

Every approach answers two questions, and the names below are built from the
answers:

1. **Who presents the identity?** A **sidecar** running beside the agent
   (Pattern A), or the **agent itself** (Pattern B).
2. **How does the identity land?** As an injected **token**, an **mTLS tunnel**,
   a **self-minted SVID**, or a **relayed platform token**.

Read a name and you already know what it does: the *pattern* says who presents,
the *variant* says how it lands.

## The approaches

| | Variant | The agent's request carries… | Validated by |
|---|---|---|---|
| **A — Sidecar-Presented Identity** | | *A co-process presents identity; the agent sends a plain local request and stays identity-unaware.* | |
| A1 | [Sidecar Token Injection](sidecar-injected-token.md) (Robin) | an `Authorization: Bearer` token the sidecar adds | `jwt` / `kubernetes` / `spiffe` |
| A2 | [Sidecar mTLS Tunnel](sidecar-tunneled-cert.md) (ghostunnel) | nothing — identity rides the mTLS channel the sidecar originates | `cert` / `spiffe` |
| **B — Agent-Presented Identity** | | *The identity-aware agent attaches its own credential.* | |
| B1 | [Self-Minted SVID](self-minted-identity.md) | an SVID the agent fetched from the Workload API | `spiffe` |
| B2 | [Platform Token Relay](platform-issued-token.md) | a token the platform issued (projected SA token, CI OIDC) | `kubernetes` / `jwt` |

All four are **transparent authentication** — the agent points an ordinary
client at Warden, sends no Warden session token, and re-presents its credential
on each request. Warden validates it in line and caches the result. See
[transparent authentication](../concepts/authentication.md#transparent-authentication).

## Choosing

```
Is the agent identity-aware?
├── no → Pattern A (a sidecar presents identity)
│        Is the credential a bearer token or a certificate?
│        ├── token → A1  Sidecar Token Injection   (Robin)
│        └── cert  → A2  Sidecar mTLS Tunnel        (ghostunnel)
│
└── yes → Pattern B (the agent presents its own credential)
         Does the agent mint its own SVID, or relay one the platform issued?
         ├── mints  → B1  Self-Minted SVID
         └── relays → B2  Platform Token Relay
```

- **Reach for Pattern A** when you do not want to change the application: it
  speaks plain HTTP on loopback to the sidecar and carries no secret. This is the
  common shape for agents and off-the-shelf workloads.
- **Reach for Pattern B** when the agent is already identity-aware — it links a
  SPIFFE library (B1) or runs on a platform that hands it a token (B2) — and you
  would rather not run a co-process.

## See Also

- [Authentication](../concepts/authentication.md) — the credential forms, auth
  methods, and transparent auth these approaches build on.
- [Tokens](../concepts/tokens.md) — what authentication produces.
- [Agent Flow](../agent-flow.md) — the end-to-end path once identity is
  established.
- [Workstation quickstart 03 — SPIFFE](../quickstarts/workstation/03-spiffe-llm-mcp/)
  — a keyless, auto-rotating SVID in practice.
