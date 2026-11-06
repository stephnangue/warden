---
title: "Human operators"
---

People who run Warden sign in with their own identity provider, the one they
already use for everything else. They do not become entities: Warden keeps no
record of them in the identity store. A sign-in issues a **ticket**, a session
that carries who the person is and what their identity provider verified, and
nothing about what they may do. Each request names a role, and
[virtual groups](/identity/groups/) whose rules match the person's claims grant
it, or not, on that request.

<p align="center"><img alt="A person, who has no entity, presents a ticket token and asks for the role warden-viewer. Authenticate: Warden checks the ticket. Resolve: of two virtual groups, attaching warden-admin and warden-viewer, the one whose rules match the facts the ticket carries resolves warden-viewer. Authorize: warden-viewer is among them, so the request is authorized." src="/images/warden-human-virtual-group.png" width="860"></p>

So who may do what is managed where it is already managed: add someone to the
right group or app role at the identity provider, and the virtual group that
matches it gives them the role.

## How a sign-in works

1. `warden login` asks the `oidc` auth mount to start a sign-in, and opens the
   browser at the identity provider.
2. The person signs in there. The identity provider sends the browser back to
   a listener the CLI runs on `http://localhost:8251/oidc/callback`.
3. The mount redeems the authorization code, using PKCE and its own client
   authentication, and verifies the ID token.
4. Warden issues a ticket and the CLI saves it as the session for the
   commands that follow. It then lists the roles the person's groups grant and
   asks which one to use.

The mount stores nothing while a sign-in is in flight: the pending login is
sealed into the OAuth `state`, so a sign-in survives a restart or a failover.

## Set it up

The steps below sign people in through Microsoft Entra ID and give
`warden-viewer`, one of the [built-in roles](/identity/built-in-roles/), to
everyone holding the `Warden.Viewer` app role. Registering Warden at the
identity provider, and the settings each provider needs, are covered in
[OIDC auth method](/auth-methods/oidc/). Register the redirect URI
`http://localhost:8251/oidc/callback`.

Enable the auth method:

```bash
warden auth enable oidc
```

Configure it. The discovery document is fetched when the configuration is
written, and a write the identity provider does not back up is refused:

```bash
warden write auth/oidc/config '{
  "oidc_discovery_url": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "<application-id>",
  "client_auth": "client_secret",
  "client_secret": "<client-secret>",
  "allowed_redirect_uris": ["http://localhost/oidc/callback"],
  "facts": {
    "oid": "oid",
    "roles": "app_roles"
  },
  "alias_name_source": "oid",
  "session_ttl": "4h"
}'
```

`facts` maps an ID token claim to the fact name groups match: here Entra's
`roles` claim becomes the fact `app_roles`. `alias_name_source` takes the
person's identity from `oid`, which Entra keeps stable for a user across
applications. A JSON argument containing `=` is read as `key=value` pairs:
when a value holds one, put the JSON in a file and pass it on stdin
(`warden write auth/oidc/config < oidc.json`).

Grant the role through a virtual group:

```bash
warden identity group create viewers -json '{
  "type": "virtual",
  "description": "People holding the Warden.Viewer app role",
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

Then sign in:

```bash
warden login
```

```
Opening the browser to sign in through auth/oidc/…
Signed in to namespace root; session valid until 18:30 (4h0m0s).
Using role "warden-viewer" for warden commands. Switch with: warden role use
```

## The oidc mount

| Setting | What it does |
|---|---|
| `oidc_discovery_url` | The identity provider's issuer. ID tokens must carry it as `iss`. |
| `oidc_discovery_ca_pem` | The CA the identity provider's TLS chains to, when it is not a public one. |
| `client_id` | Warden's client ID at the identity provider. ID tokens must carry it as `aud`. |
| `client_auth` | How Warden authenticates when it redeems the code: `client_secret` (the default), `private_key_jwt`, or `none` for a public client. |
| `client_secret` | For `client_secret`. Never read back. |
| `private_key`, `client_assertion_kid` | For `private_key_jwt`: the PEM RSA key that signs the client assertion, and the key ID the identity provider knows it by. The key is never read back. |
| `client_certificate` | Optional, for `private_key_jwt`: the key's certificate. Its SHA-256 thumbprint goes in the assertion's `x5t#S256` header, for an identity provider that identifies the key by its certificate. |
| `allowed_redirect_uris` | Required. Matched exactly, except that a loopback URI matches on any port: `http://localhost/oidc/callback` allows `warden login` on any `-callback-port`. |
| `scopes` | Default `openid`, `profile`. `openid` is required. |
| `supported_algs` | ID token signing algorithms accepted. Default `RS256`. |
| `facts` | Claim (or a JSON Pointer into nested claims) to fact name. `sub`, `iss` and `aud` are always published. A write replaces the whole map. |
| `alias_name_source` | The fact a person's identity is taken from. Default `sub`. |
| `session_ttl` | How long a ticket lasts. Default `1h`, at most `8h`. |
| `entity_kind` | Always `human`: this mount admits people only. |

A stored configuration that no longer validates is kept and readable, but
refuses sign-ins until it is written again.

## `warden login`

| Flag | Default | What it does |
|---|---|---|
| `-path` | `oidc` | The auth mount to sign in through, under `auth/`. |
| `-method` | `oidc` | The auth method. `oidc` is the one interactive method. |
| `-callback-port` | `8251` | Port of the redirect `http://localhost:<port>/oidc/callback`. `0` picks a free one, for an identity provider that accepts any loopback port. |
| `-no-browser` | off | Print the sign-in URL instead of opening a browser. |
| `-timeout` | `5m` | How long to wait for the sign-in to finish in the browser. |
| `-force` | off | Sign in again even when the current session is still valid. |
| `-no-store` | off | Print the ticket on stdout instead of saving a session. |

The global `-role` (or `WARDEN_ROLE`) and `-namespace` (or `WARDEN_NAMESPACE`)
also apply.

**Choosing a role.** A role named with `-role` is checked and used. Otherwise,
when the person's groups grant one role, it is used; when they grant several,
a picker opens on the terminal (arrows to move, type to filter, Enter to
select). Without a terminal the roles are listed on stderr. Switch later
without signing in again:

```bash
warden role use                  # pick from the list
warden role use warden-viewer    # or name it
```

`-role` and `WARDEN_ROLE` still override the session's role for one command.

**Keeping a session.** When a session of the same namespace and mount has more
than five minutes left, and the server still accepts it, `warden login` keeps
it and only applies the role `-role` names. Use `-force` to sign in again.

## The session on your machine

Sessions live in `~/.warden/sessions/` (mode `0700`), one `0600` file per
Warden address and namespace.

- **Precedence.** For the role and the namespace: the flag, then the
  environment, then the session. For the credential: when `WARDEN_TOKEN` or
  `WARDEN_CLIENT_CERT` is set, no session is sent at all, and a session's role
  is never sent with another credential.
- **Namespaces.** In a namespace with no session of its own, commands use the
  nearest parent's and say so (`using session from namespace …`).
- **Expiry.** An expired session is not sent; the command runs without it,
  after a notice.

`warden logout` forgets the session in use. The ticket itself stays valid
until it expires. `warden print token` prints it, for other tools:

```bash
curl -H "Authorization: Bearer $(warden print token)" \
     -H "X-Warden-Role: warden-viewer" \
     "$WARDEN_ADDR/v1/sys/roles?warden-list=true"
```

## Tickets

A ticket value starts with `wdt.`. It is self-contained and encrypted under
Warden's own key: it holds the person's identity, the kind `human`, the claims
the mount maps, the namespace and mount that issued it, and its issue,
authentication and expiry times. It holds no role, no policy and none of the
identity provider's tokens, and it is never stored server side.
See [Tokens](/identity/tokens/) for how it compares with the other kinds.

On every request Warden checks that the ticket has not expired, that the mount
that issued it still exists in its namespace, and that the request's
namespace is that namespace or one below it.

**A ticket cannot be revoked before it expires.** Keep `session_ttl` short. To
end every session a mount issued at once, disable the mount; deleting the
namespace does the same. Re-enabling a mount at the same path does not bring
old tickets back.

**What changes apply.** Changes to groups and roles apply on the person's next
request. The claims are fixed at sign-in: when someone is added to or removed
from a group at the identity provider, the change reaches Warden at their next
sign-in (`warden login -force`). Only the claims the mount maps at sign-in are
kept in the ticket, so a claim mapped later reaches existing sessions only
after a new sign-in too.

**Presenting it.** A ticket is accepted on `X-Warden-Token` or as an
`Authorization: Bearer` token, nowhere else. The role is asked for the way the
path asks for one: `?role=` or `X-Warden-Role` on Warden's own API, and the
provider's usual way, such as the `role/<role>/` segment, on a gateway. The
discovery endpoints take no role: they list what the ticket's groups grant.
A request that needs a role and names none is refused with `400`.

## Roles for people

People are granted roles by virtual groups, with rules over the facts their
mount publishes. A static group lists entities, and people are not entities.

- Every rule names the mounts it trusts with `mount`. Add `"kind": ["human"]`
  to make a rule's intent explicit; a rule over a mount glob then never
  matches an agent from another mount.
- One rule per identity provider group or app role keeps the mapping readable.
  A group can carry several rules; a caller matching any one holds its roles.
- Roles granted to people are ordinary roles. A person can call a provider's
  gateway under a role with a credential spec, the way an agent does. The
  [built-in roles](/identity/built-in-roles/) are for operating Warden itself
  and never reach a data plane.

The audit log records, for each request, the ticket's issuing mount, the
person's authentication time and the group that granted the role. The ticket
value itself never reaches it.

## Namespaces

A ticket is issued in the namespace of its mount, and acts there and in every
namespace below it. Its role is always granted by the groups and roles of the
namespace that issued it, whichever namespace the request goes to.

**Central administration.** Enable one `oidc` mount in root and write the
groups there. A person signs in once, and the session serves every namespace
below. In a child namespace they hold what root's groups grant them, never
what the child's groups grant. The policies of a role granted this way are
compiled in root, so they must name the child's paths. The built-in roles
already reach every namespace below the one that grants them.

**Tenant administration.** Enable an `oidc` mount in the tenant namespace,
with the tenant's own identity provider if it has one, and write the groups
there. Those people sign in with `-namespace`:

```bash
warden login -namespace acme
```

Their session serves `acme/` and the namespaces below it, and nothing above or
beside it.

## See also

- [OIDC auth method](/auth-methods/oidc/) — registering Warden at your identity provider.
- [Built-in roles](/identity/built-in-roles/) — the four operator roles to grant people.
- [Groups](/identity/groups/) — virtual group rules and selectors.
- [Tokens](/identity/tokens/) — tickets beside the other token kinds.
- [Namespaces](/concepts/namespaces/) — the namespace hierarchy.
