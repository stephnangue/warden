# Auth Methods

An **auth method** is a backend you mount under a path; it validates the
credential a caller presents and issues a token carrying a set of policies. Every
method in this family also participates in **transparent authentication** — the
workload presents the credential it already holds on each request and Warden
resolves an identity in-line, with no separate login step. See
[Authentication](../concepts/authentication.md) for the model and
[Roles](../concepts/roles.md) for how a validated credential maps to policies.

Warden ships four auth methods. Each page below is a setup guide — prerequisites,
configuration, roles, transparent-auth wiring, a configuration reference, and
troubleshooting.

| Method | Validates | Reach for it when |
|--------|-----------|-------------------|
| [Certificate](cert.md) | an X.509 client certificate against a configured CA bundle and role constraints | workloads carry a long-lived or mesh-issued certificate, or run in air-gapped networks where an IdP isn't reachable per login. |
| [JWT / OIDC](jwt.md) | a signed JWT against an OIDC discovery URL, a JWKS endpoint, or static public keys | workloads carry tokens from an OIDC provider, or you need claim-driven role mapping. |
| [Kubernetes](kubernetes.md) | a Kubernetes ServiceAccount token via the issuing cluster's TokenReview API | in-cluster pods should authenticate by their ServiceAccount without distributing JWKS or OIDC config. |
| [SPIFFE](spiffe.md) | a SPIFFE identity — **either** an X.509-SVID or a JWT-SVID — against a trust-domain bundle | workloads run in a SPIRE/mesh deployment that mints SVIDs, possibly federated across trust domains. |

Not sure which fits? The opening of each page spells out exactly when to prefer it
over its neighbours — the [JWT](jwt.md), [Kubernetes](kubernetes.md), and
[SPIFFE](spiffe.md) pages all overlap on bearer-token shapes, and the
[Certificate](cert.md) page covers what mTLS buys you over a bearer token.

## See Also

- [Authentication](../concepts/authentication.md) — credential forms, explicit vs. transparent auth, and CLI behaviour.
- [Roles](../concepts/roles.md) — how a validated credential maps to policies and token settings.
- [Agent Identity](../agent-identity/README.md) — how a workload or its sidecar presents its credential to Warden.
- [`warden auth`](../cli/auth.md) — the CLI for enabling, listing, and disabling auth methods.
- [Concepts](../concepts/README.md) — how Warden works, end to end.
