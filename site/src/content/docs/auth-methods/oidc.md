---
title: "OIDC"
---

The `oidc` auth method signs **people** in: operators who run Warden from
the CLI, with the identity provider they already use. It runs the OpenID
Connect authorization code flow with PKCE, driven by `warden login` from a
loopback redirect, and issues a **ticket** (a `wdt.` token) that lasts the
mount's `session_ttl`. Agents and workloads use the other auth methods.

People are never entities. A ticket carries the person's native identity and
the ID token claims the mount maps, and no role: each request asks for one,
and [virtual groups](/identity/groups/) whose rules match those claims grant
it. This page is the reference for the mount. How sign-in, sessions and role
choice work for the person is covered in
[Human operators](/identity/human-operators/).

## Prerequisites

- A **Warden server** unsealed, reachable from the operators' machines.
- An **OpenID Connect provider** with a discovery document, where you can
  register an application.
- The **roles** you want to grant, for example the
  [built-in roles](/identity/built-in-roles/).

## Step 1: Register Warden at the identity provider

`warden login` listens on `http://localhost:8251/oidc/callback` and sends that
as the redirect URI. Register it exactly. `-callback-port` changes the port:
Entra ignores the port on a `localhost` redirect URI, so one entry covers
every port; other identity providers may need each port registered.

### Microsoft Entra ID

1. **Create the app registration.** In the Entra admin center, under
   *App registrations*, create an application for your tenant. Note the
   *Application (client) ID* and the *tenant ID*.
2. **Add the redirect URI.** Under *Authentication*, add a platform and the
   redirect URI `http://localhost:8251/oidc/callback`. With `client_auth`
   `client_secret` or `private_key_jwt`, Warden is a confidential client:
   use the *Web* platform. With `client_auth` `none`, use *Mobile and desktop
   applications*, which Entra treats as a public client. Entra refuses a
   client secret or assertion from a public client. Entra ignores the port
   when it matches a `localhost` redirect URI, so this one entry covers every
   `-callback-port`; don't add entries that differ only in the port.
3. **Leave implicit grant off.** Warden redeems the code at the token
   endpoint and takes the ID token from that response; the *ID tokens
   (used for implicit and hybrid flows)* checkbox is not needed.
4. **Create a client credential.** Under *Certificates & secrets*, add a
   client secret, or upload the certificate of an RSA key for
   `private_key_jwt`.
5. **Define app roles.** Under *App roles*, create one per level of access,
   for example `Warden.Viewer`, allowed for users and groups. Assign people or
   groups to them on the matching *Enterprise application*. An assigned app
   role reaches the ID token in the `roles` claim. Setting *Assignment
   required* on the enterprise application keeps everyone else from signing
   in at all.
6. **Or emit groups.** *Token configuration → Add groups claim* (the
   manifest's `groupMembershipClaims`) puts group object IDs in the `groups`
   claim. Prefer *Groups assigned to the application*: a person in more groups
   than Entra puts in a token gets no `groups` claim but a reference to fetch
   them, which Warden refuses (see [Limits](#limits-and-refusals)).
7. **Add `auth_time`.** Entra's ID tokens omit it by default. Add it as an
   optional claim of the ID token under *Token configuration*. Warden records
   it in the audit log as the person's authentication time; without it, the
   token's `iat` is used.
8. **Enforce MFA and sign-in frequency at Entra.** Warden does not ask for a
   second factor. A Conditional Access policy targeting this application can
   require MFA and set a sign-in frequency. It governs sign-in only: a ticket
   already issued lasts until `session_ttl` ends.

Use the tenant-specific issuer
`https://login.microsoftonline.com/<tenant-id>/v2.0` as
`oidc_discovery_url`. The multi-tenant `common` and `organizations` endpoints
publish a templated issuer, which never equals the URL, so discovery fails.

Keep `profile` in the scopes: Entra includes `oid`, the user's object ID,
only with it. `oid` is the same for the user across the tenant's
applications, while `sub` is specific to each application, which makes `oid`
the better native identity.

### Other identity providers

Any OpenID Connect provider works the same way: a confidential (or public)
client with the authorization code grant, the redirect URI above, and a
claim listing each person's groups or roles in the ID token. The issuer the
provider publishes must equal `oidc_discovery_url` exactly, trailing slash
included. Check your provider's documentation for how it names that claim
and how many values it puts in a token.

## Step 2: Enable and configure the mount

```bash
warden auth enable oidc
```

This mounts at `auth/oidc/`, the mount `warden login` uses by default. Use
`-path` for another one, and `warden login -path=<name>` to reach it.

Write the configuration. The discovery document is fetched before anything is
stored, and its issuer must equal `oidc_discovery_url`:

```bash
warden write auth/oidc/config '{
  "oidc_discovery_url": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "<application-id>",
  "client_auth": "client_secret",
  "client_secret": "<client-secret>",
  "allowed_redirect_uris": ["http://localhost/oidc/callback"],
  "scopes": ["openid", "profile"],
  "facts": {
    "oid": "oid",
    "roles": "app_roles"
  },
  "alias_name_source": "oid",
  "session_ttl": "4h"
}'
```

`warden write` reads a JSON argument as `key=value` pairs when it contains an
`=`. When a value holds one, put the JSON in a file and pass it on stdin:
`warden write auth/oidc/config < oidc.json`.

A write merges onto the stored configuration: keys not sent are kept,
secrets included. Changing `client_auth` drops the stored client secret,
private key and certificate unless the same write sends them. Switching to a
certificate, with the PEM files folded into JSON by `jq`:

```bash
jq -n --rawfile key warden-oidc.key --rawfile cert warden-oidc.crt '{
  "client_auth": "private_key_jwt",
  "private_key": $key,
  "client_certificate": $cert
}' | warden write auth/oidc/config
```

`warden read auth/oidc/config` shows the configuration; `client_secret` and
`private_key` are never read back.

## Step 3: Grant roles with a virtual group

Every ticket the mount issues answers these facts, which group rules match:

| Fact | Value |
|---|---|
| `sub` | The ID token's `sub`. |
| `iss` | The ID token's `iss`, equal to `oidc_discovery_url`. |
| `aud` | The ID token's `aud`, which includes `client_id`. |
| `kind` | Always `human`. |
| `mount` | The mount's path in its namespace, e.g. `auth/oidc/`. |
| *mapped* | Each claim named in `facts`, under the fact name it maps to. |

Every other claim is dropped at sign-in. With the configuration above, grant
`warden-viewer` to everyone holding the `Warden.Viewer` app role:

```bash
warden identity group create entra-viewers -json '{
  "type": "virtual",
  "description": "People holding the Warden.Viewer app role in Entra",
  "roles": ["warden-viewer"],
  "rules": [
    {
      "mount": ["auth/oidc/"],
      "kind": ["human"],
      "app_roles": ["Warden.Viewer"]
    }
  ]
}'
```

To match Entra groups instead, map `"groups": "entra_groups"` in `facts` and
write the rule over `entra_groups` with the groups' object IDs.

## Step 4: Sign in

```bash
warden login
```

The browser opens at the identity provider. Once the person signs in, the
CLI saves the session and picks a role among those the groups grant. Flags,
role choice and the session on disk are described in
[Human operators](/identity/human-operators/#warden-login).

## Configuration reference

| Key | Type | Default | Meaning |
|---|---|---|---|
| `oidc_discovery_url` | string | required | The issuer. Discovery reads `<url>/.well-known/openid-configuration`; the published issuer and every ID token's `iss` must equal it. |
| `oidc_discovery_ca_pem` | string | system roots | PEM CA certificate the identity provider's TLS chains to, when not a public one. |
| `client_id` | string | required | Warden's client ID at the identity provider. ID tokens must carry it as `aud`. |
| `client_auth` | string | `client_secret` | How Warden authenticates when it redeems the code: `client_secret` (HTTP Basic), `private_key_jwt` (an RS256 client assertion, audience the token endpoint), or `none` (a public client; PKCE only). |
| `client_secret` | string | none | Required with `client_secret`, refused otherwise. Never read back. |
| `private_key` | string | none | PEM RSA private key (PKCS#1 or PKCS#8) signing the assertion. Required with `private_key_jwt`, refused otherwise. Never read back. |
| `client_certificate` | string | none | Only with `private_key_jwt`, optional: the PEM certificate of `private_key`. Its SHA-256 thumbprint is sent as the assertion's `x5t#S256` header. It must certify the key. |
| `client_assertion_kid` | string | none | Key ID sent as the assertion's `kid`, for a provider that looks the key up by it. |
| `supported_algs` | list | `RS256` | ID token signing algorithms accepted: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `EdDSA`. |
| `allowed_redirect_uris` | list | required | Redirect URIs a sign-in may use, matched exactly. A loopback entry (`localhost`, `127.0.0.1`, `::1`) matches on any port, so `http://localhost/oidc/callback` allows every `-callback-port`. The CLI always sends host `localhost`. |
| `scopes` | list | `openid`, `profile` | Scopes requested. `openid` is required. |
| `session_ttl` | duration | `1h` | How long a ticket lasts, at most `8h`. `0` restores the default. A ticket cannot be revoked before. |
| `facts` | map | empty | ID token claim (or a JSON Pointer with a leading `/` into a nested claim) to the fact name it is published as. At most 32 entries; names use `a-z`, `0-9`, `_ . : / -`, at most 64 bytes, never `mount` or `kind`. A write replaces the whole map. |
| `alias_name_source` | string | `sub` | The fact whose first value is the person's native identity: a built-in (`sub`, `iss`, `aud`) or a mapped fact. An empty value restores the default. |
| `entity_kind` | string | `human` | Fixed: any other value is refused. |

Lists take a JSON array or a comma-separated string. A stored configuration
that no longer validates stays readable but refuses every sign-in until it is
written again.

## Limits and refusals

- **Distributed claims.** When the ID token lists a mapped claim in
  `_claim_names` instead of carrying it (OpenID Connect distributed claims,
  how Entra signals a groups overage), the sign-in is refused: matching it
  would see no values, and the person would silently lose every group it
  grants. Use app roles, or groups assigned to the application.
- **Ticket size.** A ticket travels in one header, bounded at 8000 bytes,
  prefix included. Only mapped claims count, but a mapped list of group
  object IDs (36 characters each) fills it at roughly 140 entries, fewer with
  other mapped claims. A sign-in whose ticket would exceed the bound is
  refused with its size; map fewer claims, or claims with fewer values.
- **Native identity.** A sign-in whose `alias_name_source` yields no value is
  refused.
- **Claims are fixed at sign-in.** A change at the identity provider reaches
  Warden at the next sign-in (`warden login -force`). The identity provider's
  access and refresh tokens are discarded, so nothing renews a ticket.
- **Expiry.** An expired ticket is refused on every request. The CLI stops
  sending it, warns `session expired; run warden login`, and runs the command
  without a credential.
- **Disabling the mount** (`warden auth disable oidc/`) ends every ticket it
  issued from the next request on. Enabling it again at the same path does
  not bring them back.
- **Sign-in window.** A sign-in must finish within 10 minutes of starting.
  The pending login is sealed into the OAuth `state`, so the mount stores
  nothing and a sign-in survives a failover.

## Troubleshooting

**The configuration write fails with `discovery at <url>: …`.** Warden could
not fetch the discovery document, or its issuer differs from
`oidc_discovery_url`. Use the tenant-specific Entra URL, match the published
issuer character for character, and set `oidc_discovery_ca_pem` for a
private CA.

**`warden login` fails with `no oidc auth mount at auth/oidc/ in this
namespace; name it with -path`.** The mount lives elsewhere, or in another
namespace: pass `-path` or `-namespace`.

**`the oidc auth method is not configured`** (400) or **`the oidc auth
method's configuration is invalid; rewrite it`** (503). Write the
configuration. **`the identity provider cannot be reached`** (503): the
discovery document could not be fetched at sign-in; the server log has the
reason.

**`redirect_uri is not one of the mount's allowed_redirect_uris`.** Add
`http://localhost/oidc/callback`. An entry with host `127.0.0.1` does not
match the CLI's `localhost`.

**`port 8251 is in use: choose another with -callback-port …`.** Another
process holds the port. Pick another and register that redirect URI at the
identity provider.

**`the identity provider refused the login: <error>: <description>`.** The
provider's own error, relayed. With Entra, `AADSTS50011` names a redirect URI
mismatch; `AADSTS50105`, a person not assigned to the application when
assignment is required.

**`the identity provider did not complete the login, or its ID token did not
verify`** (401). The code exchange or the ID token check failed: a wrong
client secret or certificate, a public client sending a secret, an
`aud` or `iss` mismatch, or an algorithm outside `supported_algs`. The server
log names the cause (`oidc login refused`).

**`the login state is invalid or has expired; start the login again`.** The
sign-in took more than 10 minutes, or the state was altered. Run
`warden login` again.

**`timed out waiting for the sign-in to finish in the browser`.** Finish
sooner, or raise `-timeout` (default `5m`).

**`the ID token delivers claim "groups" elsewhere (distributed claims) …`.**
See [Limits](#limits-and-refusals).

**`the session would be <n> bytes (limit 8000) …`.** Map fewer claims, or
emit only the groups assigned to the application.

**`warning: no group grants you a role in this namespace`.** The sign-in
worked but no virtual group matched. Check the rule's `mount` (the path in
the mount's namespace, e.g. `auth/oidc/`), that the claim is mapped in
`facts`, and that the value matches what the ID token carries.

**Requests fail with `the presented ticket is not valid here`.** The ticket
expired, its mount was disabled, or the request went to a namespace outside
the ticket's own. Sign in again.

## See Also

- [Human operators](/identity/human-operators/) — sign-in, sessions and role choice for people.
- [Groups](/identity/groups/) — virtual group rules and selectors.
- [Built-in roles](/identity/built-in-roles/) — the operator roles to grant people.
- [Tokens](/identity/tokens/) — tickets beside the other token kinds.
- [Auth Methods](/auth-methods/) — the auth methods for agents and workloads.
