---
title: "OAuth 3LO credential store"
description: "Configure an OpenBao/Vault OAuth app secret engine so Warden can broker a user's OAuth access token, and gate it with a templated policy."
---

Several providers broker an access token that belongs to a **user**, not to the agent and not
to the mount: a Slack token that can post only where that person can post, a GitHub token
that sees only their repositories. Three-legged OAuth produces such a token, but it arrives
with a refresh token attached — a long-lived, high-value secret that Warden should never hold.

The [OAuth app secret engine](https://github.com/openbao/openbao-plugin-secrets-oauthapp) for
OpenBao/Vault holds it instead. The user consents once, the refresh token is stored in the
engine, and from then on the engine mints a fresh access token whenever one is read. Warden
reads one whenever it needs a fresh one, and injects it.

:::note[The access token is not stored — it is minted]
What the engine keeps is the **refresh token** and the consent behind it. Each read mints a
current access token from it, refreshing upstream when the previous one has expired. Reading
the credential is therefore a mint, not a lookup, and the value Warden caches is bounded by
the token's own expiry rather than by anything Warden decides.
:::

This page covers the store side — the part that lives in OpenBao/Vault rather than in Warden.
For the Warden-side keys, see the [Vault credential driver](/credential-drivers/vault/).

## How a request resolves

1. The agent calls Warden carrying the user's identity as well as its own.
2. Warden mints an identity assertion. Its `sub` is the **agent**; the user travels in a
   nested `warden_user` claim.
3. Warden logs in to OpenBao/Vault with that assertion at the JWT auth mount.
4. Warden reads `<oauth2_mount>/creds/<credential_name>`, where `credential_name` is
   resolved from the caller's claims.
5. The engine returns an access token minted from that user's stored refresh token.
6. Warden injects it upstream.

Two independent decisions gate step 4, and this page is mostly about keeping them aligned:

| Gate | Enforced by | Decides |
|---|---|---|
| **1. May this caller use this spec at all?** | A Warden policy | Whether the request reaches the mount |
| **2. May this identity read *that* credential name?** | A templated ACL policy in the store | Which single credential the login can read |

## Prerequisites

- An OpenBao/Vault instance with the [OAuth app secrets plugin](https://github.com/openbao/openbao-plugin-secrets-oauthapp)
  registered. Installing an external plugin is out of scope here.
- A JWT auth mount configured to trust Warden's OIDC issuer — see
  [Keyless credentials](/federation/keyless-credentials/).
- An OAuth application registered with the upstream provider (client id, client secret, and
  a redirect URL you control).

## Step 1: Enable the engine and register the server

```bash
bao secrets enable -path=oauth2 oauthapp

bao write oauth2/servers/slack \
    provider=slack \
    client_id=<your-client-id> \
    client_secret=<your-client-secret>
```

`provider` selects the built-in endpoint set — `slack`, `github`, `gitlab`, `google`,
`microsoft_azure_ad`, `bitbucket`, `oidc`, or `custom` for a provider you describe by hand.
A mount can hold several servers; each named credential records which one it came from. The
[plugin's documentation](https://github.com/openbao/openbao-plugin-secrets-oauthapp) carries
the current provider list and the per-provider options each one accepts.

## Step 2: Enroll a user

This is the three-legged part, and it happens **once per user**, out of band from any agent
traffic.

Generate the authorization URL:

```bash
bao write oauth2/auth-code-url \
    server=slack \
    state=<random-per-enrollment-value> \
    scopes=chat:write,channels:read \
    redirect_url=https://enroll.example.com/callback
```

Send the user to the returned URL. They sign in to the provider, approve the scopes, and the
provider redirects to your registered redirect URL carrying a `code`. Exchange that code for
a stored credential:

```bash
bao write oauth2/creds/U012ABCDEF \
    server=slack \
    code=<code-from-the-redirect> \
    redirect_url=https://enroll.example.com/callback
```

`redirect_url` is optional to the engine, but when the authorization URL carried one the code
exchange must carry the same value — most providers reject the exchange otherwise.

The engine exchanges the code, keeps the refresh token, and from here on
`bao read oauth2/creds/U012ABCDEF` returns a current access token.

## Step 3: The contract — the name is the join

**The name you choose in step 2 is the contract.** It is the only thing connecting an
enrollment to the spec that will read it, and nothing checks it for you at write time.

Warden reads exactly one path:

```
<oauth2_mount>/creds/<what credential_name resolves to>
```

So `credential_name` must resolve, for a given user, to the name that user was enrolled under.

A literal value like `"credential_name": "slack-ops"` satisfies that by construction, since it
resolves to the same thing every time — but it also means every caller who can reach the spec
is handed the same person's token. That is occasionally what you want, for a shared bot
account nobody owns personally. It is not per-user brokering.

Templating the name changes that:

```bash
warden cred spec create slack-user -json '{
  "source": "vault-keyless",
  "config": {
    "mint_method": "oauth2",
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "sub",
    "oauth2_mount": "oauth2",
    "credential_name": "{{user.sub}}"
  }
}'
```

Now one spec serves every enrolled user, and each request resolves to that caller's own
credential. The enrollment in step 2 used `U012ABCDEF` because that is what `{{user.sub}}`
resolves to for that person — their user principal id at the auth mount they logged in
through.

:::caution[Enrolling under the wrong name fails at request time, not at write time]
`warden cred spec create` accepts any template without checking that a matching credential
exists, because the substitution happens per request. A mismatch surfaces as
`no credentials returned for '<name>' on mount '<mount>'` on the first real call.

Read a user's principal id from their Warden token rather than assuming it matches their
username or email at the provider — these are frequently different, and the store has no way
to tell you so.
:::

`assertion_user_claims` is what makes `{{user.*}}` resolvable at all; listing **only `sub`**
is the minimal form and yields an identity-only `warden_user`. A spec that sets it and
receives no user principal fails closed with a 401 challenge rather than falling back to some
other credential.

To key on something other than the principal — a provider-side user id carried in the user's
login metadata, say — list that claim instead:

```json
"assertion_user_claims": "sub,slack_user_id",
"credential_name": "{{user.slack_user_id}}"
```

A claim named here that the user's token does not carry **fails the request**. Unlike agent
metadata, an absent user claim is never skipped: it scopes a security-sensitive path, so
missing it must deny rather than silently widen what gets read.

## Step 4: The second gate — a templated policy

Everything so far would work with a policy granting `read` on `oauth2/creds/*`. Don't do
that. It would mean any caller who reaches the mount can read **any** enrolled user's token
by asking for a different name — and the only thing stopping them is Warden resolving the
template correctly.

Make the store enforce it independently. This is where the assertion's shape pays off.

The JWT role decides **what the login is identified as**, and that choice is what makes or
breaks the gate. Identify it as the *user*:

```bash
bao write auth/jwt/role/warden-oauth \
    role_type=jwt \
    bound_audiences=https://vault.example.com \
    user_claim=/warden_user/sub \
    user_claim_json_pointer=true \
    bound_claims='{"warden_role":"slack-agent"}' \
    claim_mappings='{"warden_sub":"warden_agent","warden_role":"warden_agent_role","warden_namespace":"warden_namespace"}' \
    token_policies=warden-oauth-user
```

`user_claim` names the claim that "will be used as the name for the Identity entity alias
created due to a successful login", and `user_claim_json_pointer=true` lets it reach the
nested `warden_user` claim. So each user gets their **own** entity alias, named by their
principal id — the same value `{{user.sub}}` resolves to.

The `claim_mappings` line is not part of the gate — it puts the **agent** into the store's
audit log. See [Keeping the agent in the store's audit log](#keeping-the-agent-in-the-stores-audit-log).

Then template the policy on that alias name:

```hcl
path "oauth2/creds/{{identity.entity.aliases.<jwt_mount_accessor>.name}}" {
  capabilities = ["read"]
}
```

Substitute the accessor of your JWT auth mount (`bao auth list -detailed`).

The login can now read exactly one credential — the one belonging to the user it
authenticated as. A spec whose `credential_name` resolves to anything else gets a permission
denied from the store rather than another user's token.

:::caution[Do not key the alias on the agent]
Setting `user_claim=warden_sub` (or anything else agent-scoped) looks reasonable — the
assertion's subject *is* the agent — but it collapses every user behind a given agent into
**one shared entity alias**. Scoping the path then requires `claim_mappings` to write the
user into that alias's metadata on each login, and alias metadata is last-write-wins: two
concurrent requests through the same agent for different users can interleave, so one
login's metadata is read by the other's policy evaluation. Warden is a concurrent gateway,
so this is a live race, not a theoretical one — and it fails both ways, denying a legitimate
read or authorizing the wrong name.

Keying the alias on the user avoids it entirely. The alias *name* is the identity, not
mutable state hanging off it, so nothing another login does can change what this one resolves
to.
:::

:::note[Why this composes rather than duplicating the first gate]
The two gates key on different things and fail differently. Warden's policy decides whether
this agent, acting for this user, may use the spec at all. The store decides — without
trusting Warden's templating — which row this login may read.

Both principals still gate, in different places: `bound_claims` pins **which agents** may log
in at all (the assertion carries `warden_sub`, `warden_role`, `warden_namespace` and
`warden_auth_mount` at the top level for exactly this), while the alias name scopes the
**path** to the user. That separation is possible because the assertion keeps `sub` as the
agent and carries the user nested in `warden_user`, so a verifier can bind each independently
rather than having to pick one.

One map serves the assertion claim and the template, so `{{user.sub}}` resolves to exactly
the value the policy binds. They cannot drift.
:::

### Keeping the agent in the store's audit log

Naming the alias after the user is what makes the gate safe, but on its own it would leave
the store's audit log knowing only *which user* a read was for — the agent that asked would
appear nowhere. Recover it with `claim_mappings`, which copies claim data "into the resulting
auth token **and** alias metadata".

Those two destinations behave very differently, and the distinction is the whole trick:

| Destination | Scope | Safe to template a policy on? |
|---|---|---|
| **Token** metadata | Stamped on the token minted by *this* login | — (not available to templating) |
| **Alias** metadata | Shared on the entity alias, last write wins | **No** — this is the race above |

Token metadata is per-login, so it cannot be overwritten by anyone else's login. Every audit
entry for a request made with that token carries it:

```json
{
  "type": "request",
  "auth": {
    "metadata": {
      "warden_agent": "agent-7",
      "warden_agent_role": "slack-agent",
      "warden_namespace": "root/"
    }
  },
  "request": { "path": "oauth2/creds/U012ABCDEF" }
}
```

So the store records both principals after all: the **user** in the path and the entity, the
**agent** in `auth.metadata`. The gate still keys only on the alias name, which nothing
outside this login can move.

:::caution[Map only claims the assertion always carries]
A claim named in `claim_mappings` that is absent from the JWT **fails the login**. Only
`warden_sub`, `warden_role`, `warden_namespace` and `warden_auth_mount` are emitted
unconditionally; `warden_metadata`, `warden_user` and `warden_resource` appear only when the
spec asks for them. Mapping a conditional claim makes every login fail for specs that do not
project it.
:::

Warden's own audit log remains the complete record of agent activity: because the credential
is cached per user until it expires, the store sees only the reads that miss that cache, not
one entry per agent request.

One further property is worth leaning on: **the login fails before the policy is evaluated.**
A role whose `user_claim` is absent from the JWT cannot authenticate, so a spec that forgot
`assertion_user_claims` — and therefore minted an assertion with no `warden_user` — is
rejected at login rather than logging in with an empty value and templating into an
unintended path. An empty substitution never reaches the policy.

## Putting it together

```bash
# The store, reached keylessly — no vault token in Warden
warden cred source create vault-keyless -json '{
  "type": "hvault",
  "config": {
    "vault_address": "https://vault.example.com",
    "auth_method": "oidc_federation",
    "jwt_role": "warden-oauth",
    "jwt_mount": "jwt",
    "audience": "https://vault.example.com"
  }
}'

# One spec, every enrolled user
warden cred spec create slack-user -json '{
  "source": "vault-keyless",
  "config": {
    "mint_method": "oauth2",
    "subject_token_source": "warden_identity",
    "assertion_user_claims": "sub",
    "oauth2_mount": "oauth2",
    "credential_name": "{{user.sub}}"
  }
}'
```

The credential's TTL follows the access token: the engine reports an `expire_time`, and
Warden caches no longer than that.

## Non-federated sources

A **user**-templated `credential_name` requires `subject_token_source=warden_identity`; only
`{{user.*}}` carries that requirement, since `{{agent.*}}` resolves under `agent_identity`
too. On a source authenticating with a stored token or AppRole there are no caller claims to
resolve from, and a templated name **fails closed** rather than resolving to something
arbitrary.

*When* it fails depends on the spec, not on the source. Warden test-mints a spec on write,
but skips that for any spec setting `subject_token_source` — such a spec has no caller at
creation time. So:

- **No `subject_token_source`, templated name.** The test-mint runs, the template cannot
  resolve, and `warden cred spec create` rejects it with `credential test failed ...
  credential_name references {{user.sub}} but that claim is absent from the user's projected
  claims (list it in assertion_user_claims, which requires subject_token_source=warden_identity)`.
- **`subject_token_source` set on a non-keyless source.** The spec creates fine — the
  test-mint is skipped — and the first request fails with `vault: workload identity
  federation requires auth_method=oidc_federation on the source`.

Either way the name is never resolved to something arbitrary. A literal `credential_name`
still works on such a source, but it gives up both gates: one shared credential for every
caller, and a store-side policy that cannot distinguish them. Prefer the keyless source.

## Troubleshooting

**`no credentials returned for '<name>' on mount '<mount>'`**

The read succeeded but found nothing at that name. Either the user was never enrolled, or
they were enrolled under a different name than `credential_name` resolves to. Compare
`bao list oauth2/creds` against the resolved value.

**`permission denied` reading `oauth2/creds/<name>`**

The login worked; the store's policy refused this name. Expected when `credential_name`
resolves to someone else's credential — which is the gate working.

If it happens for the *right* name, check in this order: the mount accessor in the policy
template matches the JWT mount (`bao auth list -detailed`); the role's `user_claim` is
`/warden_user/sub` with `user_claim_json_pointer=true`, so the alias is named for the user;
and — if the denial is intermittent under load rather than consistent — that the alias is not
keyed on something agent-scoped, which makes concurrent logins overwrite each other. See
[Do not key the alias on the agent](#step-4-the-second-gate--a-templated-policy).

**Authentication fails at the JWT mount**

The claim named by `user_claim` is absent from the assertion. Most often the spec omits
`assertion_user_claims`, so no `warden_user` claim is minted at all. Also check
`bound_audiences` against the source's `audience`, and any `bound_claims` against what the
assertion actually carries.

**`credential_name references {{user.sub}} but that claim is absent ...`**

The spec did not project it. The full message names the fix: *list it in
`assertion_user_claims`, which requires `subject_token_source=warden_identity`*. Pairing
`{{user.*}}` with `subject_token_source=user_identity` cannot populate claims at all.

**The token works but has the wrong scopes**

Scopes are fixed at enrollment by the `scopes` passed to `auth-code-url`. Changing them means
re-enrolling that user; the engine cannot widen a grant the user never approved.
