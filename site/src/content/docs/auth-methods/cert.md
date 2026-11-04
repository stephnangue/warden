---
title: "Certificate"
---

The certificate auth method admits workloads by their **TLS client certificate**. The workload presents an X.509 certificate during the TLS handshake (direct mTLS), or a trusted proxy forwards it in a header. Warden verifies the chain against the CA bundle you configure, optionally checks revocation, and records the certificate's subject and SAN fields as **facts**. It grants nothing: [groups](/identity/groups/) match the facts and grant [roles](/identity/roles/), on every request.

Two properties set certificate auth apart from the bearer-token methods (`jwt`, `kubernetes`):

- **Replay-resistant on direct mTLS.** The TLS handshake requires proof of possession of the private key, so a certificate that leaks through audit logs, a packet capture or a compromised proxy cannot be reused by another caller. A leaked JWT or ServiceAccount token, by contrast, is usable until it expires. This holds end to end only when Warden terminates TLS itself; behind a proxy that forwards the certificate in a header, see the trust-boundary note in [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden).
- **No per-call IdP dependency.** Once the workload has its certificate and key, it can authenticate to Warden without contacting any identity service. JWT auth needs the issuer's keys (at config time and on key rotation); Kubernetes auth calls TokenReview on every new token. Certificate auth is self-contained.

This is the auth method to reach for when:

- You run **long-lived workloads**: persistent services, bare-metal or VM workloads outside an orchestrator's token rotation, anything that runs for weeks under the same identity. The certificate rotates on the cadence of its CA or mesh, not of an IdP's token TTL.
- You operate in **air-gapped or constrained networks** where reaching an IdP is not an option, but a CA bundle can ship with the deployment.
- Your workloads carry **service-mesh certificates** (Istio, Linkerd, Consul Connect) and identity flows through the certificate rather than a token.
- You already terminate **mTLS at the network edge** and want Warden to use that same certificate rather than a second credential.
- You need **revocation checking**, CRL or OCSP, to cut off a compromised certificate without rotating the CA.

If your workload's identity is a Kubernetes ServiceAccount token, prefer the [`kubernetes`](/auth-methods/kubernetes/) auth method. For a JWT from an OIDC provider, prefer [`jwt`](/auth-methods/jwt/). For **SPIFFE SVIDs** with trust-domain-bound validation, use [`spiffe`](/auth-methods/spiffe/). The certificate method is the right tool when a classic X.509 certificate **is** the identity, not just transport encryption.

Coming from v0.21.0, where roles were bound on the auth mount? See [Upgrading from v0.21.0](/upgrade/from-v0-21/).

## Prerequisites

- A **Warden server** unsealed and reachable from the workload's network.
- A **PEM-encoded CA bundle** that issued (or transitively signed) the certificates your workloads present. Client certificates must allow client authentication in their extended key usage.
- A way to get the certificate to Warden: direct mTLS at the Warden listener, or a trusted reverse proxy that terminates TLS and forwards the certificate in a header. See [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden).
- The [policies](/concepts/policies/) the role you grant will carry. Admitting a certificate grants no access on its own.

## Enabling mTLS on the Listener

Certificate auth needs TLS on the Warden listener, so the client can present its certificate during the handshake. Two ways to get there:

- **Dev mode.** Use `-dev-tls` to enable TLS with generated certificates, or provide your own with `-dev-tls-cert-file`, `-dev-tls-key-file` and `-dev-tls-ca-cert-file`. See [Serving TLS](/concepts/dev-server/#serving-tls) and [Requiring client certificates](/concepts/dev-server/#requiring-client-certificates-mtls).
- **Behind a load balancer.** Place Warden behind a proxy that terminates TLS and forwards the client certificate in the `X-Forwarded-Client-Cert` or `X-SSL-Client-Cert` header.

Both paths end at the same certificate extractor; see [How the Certificate Reaches Warden](#how-the-certificate-reaches-warden) for the trust boundary.

## Step 1: Configure Trusted CAs

Enable the auth method:

```bash
warden auth enable cert
```

This mounts at `auth/cert/`. For several cert mounts, one per trust domain or issuing CA, name each with `-path`:

```bash
warden auth enable -path=cert-prod cert
warden auth enable -path=cert-staging cert
```

`-path` takes the mount name only; the CLI adds the `auth/` prefix.

Then configure the CA bundle that signs your workload certificates. A PEM bundle spans lines and its base64 often holds `=`, which makes `warden write` read a JSON argument as `key=value` pairs, so build the JSON with `jq` and pass it on stdin:

```bash
jq -n --rawfile ca ca-bundle.pem '{
  "trusted_ca_pem": $ca,
  "entity_kind": "agent",
  "alias_name_source": "uri_san",
  "facts": {
    "ou": "team"
  }
}' | warden write auth/cert/config

warden read auth/cert/config
```

`trusted_ca_pem` takes a concatenated bundle: every `-----BEGIN CERTIFICATE-----` block is loaded. A bundle with no valid certificate is refused at write time, and the config read shows how many were loaded as `trusted_ca_count`. A write merges onto the stored configuration: keys you leave out keep their value.

### Facts a certificate proves

Every admission carries `mount` (here `auth/cert/`) and `kind` (`agent`), and these fields of the verified leaf certificate:

| Fact | Value |
|---|---|
| `cn` | The subject's common name. |
| `serial` | The serial number, in decimal. |
| `ou` | Each organizational unit of the subject. |
| `org` | Each organization of the subject. |
| `dns_san` | Each DNS SAN. |
| `email_san` | Each email SAN. |
| `uri_san` | Each URI SAN, such as a SPIFFE ID. |
| `ca` | The SHA-256 fingerprint (lowercase hex) of each trust anchor the certificate was verified to. |

An empty value is not a fact: a certificate without a common name has no `cn`. On a cert mount, `facts` can only publish one of these fields again, under a name you choose; with the mapping above, `ou` is also the fact `team`. A mount maps at most 32 facts; names use lowercase letters, digits and `_ . : / -`, never `mount` or `kind`. A write of `facts` replaces the whole map.

Mapped facts reach [CEL conditions](/concepts/cel-conditions/) as `agent.metadata.<name>`, a multi-valued field joined with commas. A policy can then gate a path with `condition = "agent.metadata.team.startsWith('platform')"`. The built-in fields are not in `agent.metadata` unless you map them, to another name or to themselves (`"cn": "cn"`).

### The native identity

`alias_name_source` picks the field whose first value is the caller's **native identity**: the value an [entity](/identity/entities/) claims when you register the agent, and what audit names an unregistered caller by. It is one of `cn` (the default), `dns_san`, `email_san`, `uri_san` or `serial`.

Pick the field that is **stable for the lifetime of the workload** and unique across every CA the mount trusts. For service-mesh certificates that is usually `uri_san`. When the bundle holds more than one CA and the native identity is `cn`, the write warns: two CAs can issue the same common name, and both certificates would present one native identity. Use `uri_san`, or one mount per CA.

`principal_claim` picks, from the same five fields, the value recorded as the caller's principal in audit and as `agent.principal` in policy. It also defaults to `cn`. A certificate without a value in that field is refused.

## Step 2: Enable Revocation Checking (Optional)

By default the mount runs with `revocation_mode` `none`: chain validation only, no revocation lookup. To cut off compromised certificates without rotating the CA, enable CRL or OCSP:

```bash
warden write auth/cert/config '{
  "revocation_mode": "best_effort",
  "crl_cache_ttl": "1h",
  "ocsp_timeout": "5s"
}'
```

When revocation checking is on, Warden always tries **OCSP first, then CRL**; the mode only decides what happens when neither gives a definitive answer:

- `none` (default): chain validation only, no revocation lookup.
- `ocsp`, `crl`: strict. Refuse the certificate when OCSP and CRL both fail to give a definitive answer (the responder said good, or said revoked). The two names state intent; both probes run in both modes.
- `best_effort`: the same probes, but admit the certificate when both are inconclusive. Use it when revocation infrastructure is flaky and an OCSP outage should not refuse every caller.

If either probe says revoked, the certificate is refused whatever the mode.

OCSP responses come from the responder URL in the certificate's AIA extension; CRLs come from its distribution-point URL. A CRL is downloaded once and cached per URL (`crl_cache_ttl`, default 1h). OCSP is queried each time the mount verifies a certificate, which is only the first request with it and the first after its cached admission runs out. Both checks verify the response signature against the issuer from the verified chain, so forged CRLs and replayed OCSP responses are refused.

## Step 3: Create a Role

A role names what a caller may do: its policies, an optional credential spec Warden mints from, and how discovery describes it. Roles live in the namespace, not on the mount, so one role can be granted through several mounts.

```bash
warden role create inventory-agent -json '{
  "description": "Reads and updates the inventory service",
  "policies": ["inventory-read", "inventory-write"],
  "cred_spec_name": "inventory-api",
  "provider_path": "inventory/"
}'
```

`provider_path` names the provider mount the role is used with; the [discovery server](/concepts/discovery-and-skills/#discovering-roles) builds the role's URL from it. See [Roles](/identity/roles/) for every field.

## Step 4: Grant the Role with a Group

The mount admits every certificate that chains to a CA it trusts; which of them may assume a role is up to the groups. A **virtual group** grants its roles to every caller whose facts match one of its rules. Every rule names the mounts it trusts in `mount`, and its other selectors match certificate fields:

```bash
warden identity group create inventory-agents -json '{
  "type": "virtual",
  "description": "Inventory services of ExampleCorp",
  "roles": ["inventory-agent"],
  "rules": [
    {
      "mount": ["auth/cert/"],
      "kind": ["agent"],
      "cn": ["inventory-*"],
      "org": ["ExampleCorp"]
    }
  ]
}'
```

A certificate with a common name starting `inventory-` and the organization `ExampleCorp` may now ask for `inventory-agent`. Within a rule every selector must match; a multi-valued field such as `ou` or `dns_san` matches when any one of its values does. Across rules any one is enough.

Values are exact strings unless they hold a glob. `*` matches any run of characters except `/`, `**` matches across `/`, and `?` matches one character except `/`. That makes `*` a single path segment in a URI SAN:

| Selector | Matches |
|---|---|
| `"uri_san": ["spiffe://prod.example.org/ns/*/sa/*"]` | `spiffe://prod.example.org/ns/default/sa/api`: any namespace, any service account. |
| `"uri_san": ["spiffe://prod.example.org/**"]` | any URI under `prod.example.org`, at any depth. |
| `"dns_san": ["*.partner.example"]` | `api.partner.example`, not `partner.example`. |

The selectors match the URI as a string; they do not validate the certificate as a SPIFFE SVID. Use the `spiffe` auth method for that. A rule with only `mount` and `kind` matches every certificate the CA bundle accepts, so keep such a group's roles small. The full rule syntax is on [Groups](/identity/groups/).

Once an entity claims an agent's native identity, virtual groups no longer apply to it: it holds only what its entity's [static groups](/identity/groups/#static-groups) grant. See [What a claim changes](/identity/entities/#what-a-claim-changes) before you register an agent that already works through a virtual group.

### Several CAs on one mount

One mount can trust several CAs, for example your internal CA and a partner's. Put both in `trusted_ca_pem` and tell them apart in the group rules with the `ca` fact, so a partner certificate never matches a rule meant for internal workloads. Compute a CA's fingerprint with:

```bash
openssl x509 -in partner-ca.pem -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1
```

```bash
warden identity group create partner-readers -json '{
  "type": "virtual",
  "description": "Partner integrations, certificates from the partner CA only",
  "roles": ["partner-read"],
  "rules": [
    {
      "mount": ["auth/cert/"],
      "ca": ["<fingerprint of partner-ca.pem>"],
      "dns_san": ["*.partner.example"]
    }
  ]
}'
```

Set `alias_name_source` to `uri_san` on such a mount, or keep one mount per CA, so two CAs cannot present the same native identity.

## Step 5: Point a Provider at the Mount

Workloads never log in. The workload presents its certificate on every request, and Warden admits it in-line through the auth mount the path names:

1. On a provider's gateway, the mount is the provider's `auto_auth_path`. Elsewhere it is the namespace's `auto_auth_path`.
2. Warden verifies the chain and runs the revocation check, or reuses the admission it cached for this certificate.
3. The groups that match the facts decide whether the role the request names is granted.
4. The role's policies decide the call.

Set `auto_auth_path` on the provider the workload reaches, here a [`rest`](/provider-backends/rest/) provider mounted at `inventory/`:

```bash
warden write inventory/config '{
  "base_url": "https://inventory.internal.example.com",
  "auto_auth_path": "auth/cert/"
}'
```

The workload then names the role in the URL:

```bash
curl --cert /path/to/client.crt --key /path/to/client.key \
     --cacert /path/to/warden-ca.pem \
     "${WARDEN_ADDR}/v1/inventory/role/inventory-agent/gateway/<upstream-path>"
```

The role can also come from the `X-Warden-Role` header or the provider's `default_role`. A request that selects no role is refused with `400` before the certificate is checked. See [How a request selects a role](/identity/roles/#how-a-request-selects-a-role).

The first request with a given certificate is verified by the mount; the requests that follow reuse that admission until the mount's `token_ttl` (default one hour) runs out or the certificate's `NotAfter` passes, whichever comes first. The cache is keyed by the certificate's SHA-256 fingerprint, so a rotated certificate is verified afresh. The role is decided again on every request, so an edit to a group or a role applies from the next one.

## How the Certificate Reaches Warden

The auth method takes the workload certificate from direct mTLS or from a trusted forwarding header. Both end at the same extractor, so admission is identical whichever way it came.

**Direct mTLS.** The workload opens a TLS connection to Warden and presents its client certificate during the handshake. Warden's listener requests and verifies client certificates against the listener's CA pool, and the leaf certificate ends up on the connection state. This is the simplest setup and the right pick when nothing sits between the workload and Warden. The handshake proves the caller holds the private key, so a leaked certificate cannot be replayed by another caller.

**Trusted proxy forwarding.** The workload presents its certificate to a reverse proxy (Envoy, NGINX, HAProxy) that terminates TLS and forwards the certificate to Warden in a header (`X-SSL-Client-Cert` or `X-Forwarded-Client-Cert`). Warden trusts the header only from configured upstreams; other callers cannot inject one. This is the right pick when an ingress already terminates mTLS for other reasons.

> **Trust-boundary note.** On the forwarded-header path, proof of possession is checked at the proxy, not at Warden: by the time the certificate reaches Warden it is bytes in a header. Replay resistance therefore holds only across the part of the network the proxy controls. Anything that can inject headers between the proxy and Warden (a compromised co-located process, a misconfigured upstream-trust list, a hop through a non-mTLS internal load balancer) bypasses the binding. Keep the trusted-upstream list tight and the proxy-to-Warden path on a network you control.

Two practical notes regardless of source:

- The forwarding header is applied again on requests a standby forwards to the leader, so the certificate is available on whichever node handles the request.
- The certificate is parsed once per request and kept in the request context; admission and discovery read it from the same place.

## Discovering Roles

An agent does not need role names in advance. The MCP discovery server's `list_roles` tool returns the roles groups grant the presented certificate, each with its description, skill and URL; see [Discovery and Skills](/concepts/discovery-and-skills/#discovering-roles). Outside MCP, the same answer comes from:

```bash
curl --cert /path/to/client.crt --key /path/to/client.key \
     --cacert /path/to/warden-ca.pem \
     "${WARDEN_ADDR}/v1/sys/introspect/roles"
```

The response is `{roles: [{name, description, skill, provider_path}, ...], warnings: [...]}`. Warden admits the certificate at each auth mount a role of the namespace is reached through and lists the roles a group grants it there. Revocation is **not** checked for discovery; it runs on the actual request. Discovery is a hint, not a grant: each request is still decided on its own.

## Configuration Reference

| Field | Required | Description |
|---|---|---|
| `trusted_ca_pem` | Yes | PEM CA bundle that signs accepted client certificates. Several `-----BEGIN CERTIFICATE-----` blocks may be concatenated. Without it the mount admits no certificate. |
| `principal_claim` | No (default `cn`) | Field recorded as the caller's principal: `cn`, `dns_san`, `email_san`, `uri_san` or `serial`. |
| `token_ttl` | No (default `1h`) | How long an admission is reused before the certificate is verified again; never past its `NotAfter`. |
| `revocation_mode` | No (default `none`) | `none`, `ocsp`, `crl` or `best_effort`. |
| `crl_cache_ttl` | No (default `1h`) | How long a fetched CRL is cached per distribution-point URL, such as `30m` or `2h`. |
| `ocsp_timeout` | No (default `5s`) | Timeout of one OCSP query, such as `3s` or `10s`. CRL downloads use a longer timeout derived from it, since CRLs can be large. |
| `entity_kind` | No (default `agent`) | `agent` or `human`. |
| `facts` | No | Map of a built-in field (`ca`, `cn`, `dns_san`, `email_san`, `org`, `ou`, `serial`, `uri_san`) to a second fact name it is published as. At most 32 entries. A write replaces the whole map. |
| `alias_name_source` | No (default `cn`) | Field whose first value is the native identity: `cn`, `dns_san`, `email_san`, `uri_san` or `serial`. An empty value restores the default. |

The built-in facts are `mount`, `kind`, `cn`, `serial`, `ou`, `org`, `dns_san`, `email_san`, `uri_san` and `ca`.

## Troubleshooting

**A gateway request returns "authentication failed" with no detail.** By design, every admission failure gets the same answer, so a response cannot tell a caller which check failed. The server log carries the reason: chain not trusted, certificate expired, revoked, no value in the `principal_claim` field. Look at the log at the time of the failed call.

**"no client certificate provided", or discovery lists no roles.** No certificate reached Warden. Direct mTLS: the client sent none (curl needs `--cert` and `--key`), or the listener does not ask for one. Trusted proxy: the proxy did not forward the certificate, used a header name Warden does not read, or is not on Warden's trusted-upstream list, so the header was dropped.

**"no trusted CA certificates configured".** The mount has no `trusted_ca_pem`. Write one.

**A certificate that should be admitted is refused.** Walk through the server log:

1. Did the chain verify? If not, `trusted_ca_pem` does not cover the issuing CA, or the certificate's extended key usage leaves out client authentication.
2. Did the revocation check pass? In the strict modes (`ocsp`, `crl`), OCSP or CRL must give a definitive answer; when both fail (an unreachable responder and distribution point, or one inconclusive and the other with no URL in the certificate), the certificate is refused. Switch to `best_effort` to admit on both inconclusive, or fix the revocation infrastructure.
3. Does the certificate have a value in the `principal_claim` field? A certificate without a DNS SAN is refused when `principal_claim` is `dns_san`.

**`role "inventory-agent" is not assumable through auth/cert/: no group grants it to this caller`.** The certificate was admitted, but no group matched it. Check that the rule's `mount` is the mount's path with its trailing slash (`auth/cert/`), and compare each selector with the certificate: `openssl x509 -in client.crt -noout -subject -ext subjectAltName`. Every selector of a rule must match. The audit entry's `role_denied_reason` and `groups` say what matched. If an entity claims the caller's native identity, only its static groups apply.

**A `uri_san` selector refuses what looks like a matching URI.** `*` stops at `/`: `spiffe://example.com/*` matches `spiffe://example.com/api`, not `spiffe://example.com/api/v2`. Use one `*` per segment, or `**` to match at any depth.

**"trusted_ca_pem contains no valid certificates" at config write.** The bundle is empty, malformed, or holds no CERTIFICATE block. Check it with `openssl crl2pkcs7 -nocrl -certfile bundle.pem | openssl pkcs7 -print_certs -noout`: every certificate should print a `subject=` and an `issuer=` line.

**A config write refuses a key.** Keys that bound roles to the mount were removed. The error names each one and what replaced it.

**Requests are verified again sooner than `token_ttl`.** An admission never outlives the certificate: close to its `NotAfter`, it lasts only what is left. Renew the certificate; raising `token_ttl` does not help.

**OCSP or CRL checks are slow or time out under load.** Each revocation check is a network round trip. CRLs are cached per distribution-point URL (raise `crl_cache_ttl` to fetch less often); OCSP is not cached at this layer, but cached admissions mean only the first request with a certificate, and the first after its admission runs out, queries it. For consistent OCSP timeouts, raise `ocsp_timeout` (default 5s), or switch to `crl` where CRLs are more reliable than the responder.

## See Also

- [Authentication](/identity/authentication/): auth mounts, facts and native identities.
- [Groups](/identity/groups/) and [Roles](/identity/roles/): how an admitted caller is granted what it may do.
- [Entities](/identity/entities/): registering agents in the identity store.
- [Agent Identity](/agent-identity/): how a workload or its sidecar presents this credential to Warden.
- [Auth Methods](/auth-methods/): the other auth methods Warden ships.
