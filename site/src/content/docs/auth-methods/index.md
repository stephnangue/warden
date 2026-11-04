---
title: "Auth Methods"
---

An **auth method** is a backend you mount under a path. It verifies the
credential a caller presents and records what it verified as **facts**, one of
which becomes the caller's **native identity**. It grants nothing: roles live
in the namespace, and [groups](/identity/groups/) grant them per request by
matching those facts. See [Authentication](/identity/authentication/) for the
model and [Roles](/identity/roles/) for what a role names.

Agents never log in. A workload presents the credential it already holds on
every request, and Warden admits it in-line through the auth mount the path
names. People sign in once with `warden login` through an `oidc` mount and
carry a ticket.

Warden ships five auth methods. Each page below is a setup guide: prerequisites,
mount configuration, granting a role, a configuration reference, and
troubleshooting.

| Method | Verifies | Reach for it when |
|--------|-----------|-------------------|
| [Certificate](/auth-methods/cert/) | an X.509 client certificate against a configured CA bundle | workloads carry a long-lived or mesh-issued certificate, or run in air-gapped networks where an IdP isn't reachable. |
| [JWT](/auth-methods/jwt/) | a signed JWT against an OIDC discovery URL, a JWKS endpoint, or static public keys | workloads carry tokens from an OIDC provider, or you want roles granted from claims. |
| [Kubernetes](/auth-methods/kubernetes/) | a Kubernetes ServiceAccount token via the issuing cluster's TokenReview API | in-cluster pods should authenticate by their ServiceAccount without distributing keys. |
| [SPIFFE](/auth-methods/spiffe/) | a SPIFFE identity, **either** an X.509-SVID or a JWT-SVID, against a trust-domain bundle | workloads run in a SPIRE or mesh deployment that mints SVIDs, possibly federated across trust domains. |
| [OIDC](/auth-methods/oidc/) | a person's sign-in at your identity provider, through the authorization code flow | people run the Warden CLI and should get roles from their IdP groups or app roles. |

Not sure which fits? The opening of each page says when to prefer it over its
neighbours: the [JWT](/auth-methods/jwt/), [Kubernetes](/auth-methods/kubernetes/) and
[SPIFFE](/auth-methods/spiffe/) pages overlap on bearer tokens, the
[Certificate](/auth-methods/cert/) page covers what mTLS gives you over a bearer
token, and [OIDC](/auth-methods/oidc/) is the one method for people rather than
workloads.

Coming from v0.21.0, where roles were bound on the auth mount? See
[Upgrading from v0.21.0](/upgrade/from-v0-21/).

## See Also

- [Authentication](/identity/authentication/): auth mounts, facts, native identities, and CLI behaviour.
- [Groups](/identity/groups/) and [Roles](/identity/roles/): how an admitted caller is granted what it may do.
- [Human operators](/identity/human-operators/): `warden login`, tickets, and roles for people.
- [Agent Identity](/agent-identity/): how a workload or its sidecar presents its credential to Warden.
- [`warden auth`](/cli/auth/): the CLI for enabling, listing, and disabling auth methods.
- [Concepts](/concepts/): how Warden works, end to end.
