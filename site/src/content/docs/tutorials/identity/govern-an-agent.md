---
title: "Governing an Agent with Warden"
sidebar:
  label: "Govern an agent"
---

**Goal:** take one agent of the dev playground from unregistered to governed, then require
registration for every agent. You register it as an entity, a person accepts it as its
sponsor, a static group grants its role, and Warden refuses any agent nobody registered.
Last, you stop the agent with one command and start it again.

Every request goes through three steps: **Authenticate** (an auth mount verifies the
credential and finds its native identity), **Resolve** (Warden works out which roles the
caller holds), and **Authorize** (the role's policies decide the call). This tutorial
changes the Resolve step, one command at a time.

## Before you start

You need `curl`, `jq` and the `warden` CLI on your machine
(`curl -sL https://wardengateway.com/install.sh | bash`). Start the playground in its own
terminal, with Docker:

```bash
docker run --rm -p 127.0.0.1:8400:8400 -p 127.0.0.1:8410:8410 \
  ghcr.io/stephnangue/warden:latest -dev-playground -dev-root-token=root \
  -dev-playground-as-addr=0.0.0.0:8410
```

or with the binary: `warden server -dev-playground -dev-root-token=root`. With Docker, the
second port and `-dev-playground-as-addr` let your machine reach the playground's identity
provider on `https://localhost:8410`, where a person signs in in step 3.

In a second terminal, the **admin terminal**, set the address and the root token:

```bash
export WARDEN_ADDR=http://127.0.0.1:8400
export WARDEN_TOKEN=root
```

## 1. An unregistered agent calls Warden

Mint an identity for the agent with the playground's identity provider, call the bank's
HTTP API under the `teller` role, and list the roles the agent holds:

```bash
AGENT=$(warden dev jwt agent teller-bot)
curl -s "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me" \
  -H "Authorization: Bearer $AGENT" | jq .result
WARDEN_TOKEN=$AGENT warden role list -o ndjson | jq -r .name
```

```
{ "account": "teller-bot", "balance": 1000 }
assistant
atm
github
teller
```

The agent presents only its JWT. The `agent/` auth mount admits it, and its native
identity is the token's `sub`, `teller-bot`. No entity claims it, so the playground's
virtual groups grant its roles: every agent the identity provider signs gets all four.

## 2. Observe what `deny` would do

Read the namespace's identity config, and the last entry of the audit log:

```bash
warden identity config read
warden dev audit -limit 1 -o json \
  -F entry.auth.alias_name,entry.auth.identity_status,entry.auth.role_granted_by,entry.auth.role_group_type
```

```
| Unknown Aliases | observe |
"alias_name": "teller-bot",
"identity_status": "unclaimed",
"role_granted_by": "group:teller-agents",
"role_group_type": "virtual"
```

`observe`, the default, admits callers no entity claims, and records on every agent request
why `deny` would refuse it. `unclaimed` means no entity claims this native identity. These
entries tell you which agents to register before you switch.

## 3. Register the agent and give it a sponsor

Create the entity with a description, and **no** native identity yet:

```bash
warden identity entity create teller-bot -json '{
  "description": "Checks the balance and moves small amounts through the bank teller API",
  "profile": {
    "purpose": "banking",
    "runtime": "claude-code"
  }
}'
```

An entity is governed once it has a description and an accepted sponsor. A sponsor is a
virtual group of people, so people need a way to sign in. The playground's identity provider
signs people in for the `oidc` auth method, as the public client `warden-login`. Enable the
method and point it at the provider, whose certificate is signed by the playground's own
CA. The `agent/` mount already holds that CA:

```bash
warden auth enable oidc
warden read -o json auth/agent/config | jq '{
  "oidc_discovery_url": "https://localhost:8410",
  "oidc_discovery_ca_pem": .jwks_ca_pem,
  "client_id": "warden-login",
  "client_auth": "none",
  "supported_algs": ["ES256"],
  "allowed_redirect_uris": ["http://localhost/oidc/callback"],
  "facts": { "roles": "roles" }
}' > oidc.json
warden write auth/oidc/config < oidc.json
```

Both writes print `Success!`. The configuration is checked against the provider when it is
written. `facts` publishes the ID token's `roles` claim, so a group rule can match it. The
playground's one person, `ada@playground.example`, holds the app role `Warden.Operator`.
Create the sponsor group around it, and propose it:

```bash
warden identity group create bank-ops -json '{
  "type": "virtual",
  "description": "Bank operators, signed in through the playground identity provider",
  "rules": [
    {
      "mount": ["auth/oidc/"],
      "kind": ["human"],
      "roles": ["Warden.Operator"]
    }
  ]
}'
warden identity entity sponsor propose teller-bot -json '{
  "group": "bank-ops"
}'
```

```
warning: handover to /bank-ops is pending: a member must accept it
| Governed By     | (ungoverned: no sponsor (handover to group "bank-ops" pending)) |
| Pending Sponsor | /bank-ops  proposed by 00000000-0000-0000-0000-000000000000     |
```

Root is a member of no group, so its proposal waits for a person. Open a third terminal,
**Ada's terminal**, with no `WARDEN_TOKEN`, and sign in:

```bash
export WARDEN_ADDR=http://127.0.0.1:8400
warden login
```

Your browser opens on the playground's identity provider. It serves its own certificate, so
accept the browser's warning once. There is no sign-in form: the provider signs Ada in
straight away and sends the answer back to the listener `warden login` runs.

No browser on this machine (an SSH session, say)? Run `warden login -no-browser` instead: it
prints the URL to open. From another terminal, follow it with curl, which skips the
certificate check:

```bash
curl -skL "<the URL warden login printed>" -o /dev/null
```

`warden login` finishes in Ada's terminal with
`warning: no group grants you a role in this namespace` and `Signed in to namespace root`.
Ada now holds a ticket, saved as her session. It grants her no role, and she needs none:
the sponsor commands decide by the groups her ticket matches. In Ada's terminal, read
the agent, then accept it:

```bash
warden identity sponsor read teller-bot
warden identity sponsor accept teller-bot
```

```
| Governed By | warden                                                   |
| Sponsor     | /bank-ops  accepted by auth/oidc/ ada@playground.example |
```

The entity is governed. Nothing changed for the agent yet: no entity claims its native
identity, so its virtual groups still apply.

## 4. Grant the role, then claim the native identity

In the admin terminal, list the entity in a static group that grants `teller`, and only
then claim the agent's native identity for the entity:

```bash
warden identity group create tellers -json '{
  "type": "static",
  "description": "Agents allowed to use the bank teller API",
  "members": ["teller-bot"],
  "roles": ["teller"]
}'
warden identity alias add -json '{
  "mount": "auth/agent/",
  "name": "teller-bot",
  "to": "teller-bot"
}'
```

```
warning: native identity (auth/agent/, teller-bot) is now claimed by entity "teller-bot": virtual groups no longer grant it roles; it holds only the roles its entity's static groups grant, and none until the entity is governed
Success! Native identity "teller-bot" on auth/agent/ is claimed by entity teller-bot
```

The order matters. Once claimed, a caller gets no role from a virtual group. It holds only
what its entity's static groups grant, and only while the entity is governed and active.
Claiming first would have left the agent with no role until the sponsor and the group were
in place (see [Rolling out](/identity/entities/#rolling-out)). The agent now holds one role:

```bash
WARDEN_TOKEN=$AGENT warden role list -o ndjson | jq -r .name
curl -s "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me" \
  -H "Authorization: Bearer $AGENT" | jq .result
warden dev audit -limit 1 -o json \
  -F entry.auth.alias_name,entry.auth.entity_name,entry.auth.role_granted_by,entry.auth.role_group_type
```

```
teller
{ "account": "teller-bot", "balance": 1000 }
"alias_name": "teller-bot",
"entity_name": "teller-bot",
"role_granted_by": "group:tellers",
"role_group_type": "static"
```

## 5. Keep the role for governed agents

Mark `teller` as `governed_only`, so no virtual group grants it any more. Then mint a
second agent that nobody registered, and try the same call:

```bash
warden role update teller -json '{
  "governed_only": true
}'
STRAY=$(warden dev jwt agent stray-bot)
WARDEN_TOKEN=$STRAY warden role list -o ndjson | jq -r .name
curl -s "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me" \
  -H "Authorization: Bearer $STRAY"
```

```
warning: role "teller" is governed_only; 1 virtual group lists it and no longer grants it: teller-agents
assistant
atm
github
{"errors":["role \"teller\" requires governed membership: only a static group listing a governed entity grants it"]}
```

`stray-bot` lost `teller` but keeps the other roles: under `observe`, unregistered agents
still run. `teller-bot` holds `teller` through `tellers`, so its calls go through as before.

## 6. Require registration

Switch the namespace to `deny`, and call again as each agent:

```bash
warden identity config write -unknown-aliases=deny
curl -s "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me" \
  -H "Authorization: Bearer $STRAY"
curl -s "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me" \
  -H "Authorization: Bearer $AGENT" | jq .result
```

```
| Unknown Aliases | deny  |
{"errors":["native identity (auth/agent/, stray-bot) is unclaimed; unknown_aliases=deny"]}
{ "account": "teller-bot", "balance": 1000 }
```

Root is never judged by a native identity, so this write cannot lock you out. `stray-bot`
is refused with `403` at Resolve, before any role is considered, whichever role it asks
for. The refusal names what it presented and nothing more. The audit log records it:

```bash
warden dev audit -decision deny -limit 1
```

```
| DECISION | AGENT     | PATH                                     | REASON
| deny     | stray-bot | bank-api/role/teller/gateway/accounts/me | native identity (auth/agent/, stray-bot) is unclaimed; unknown_aliases=deny
```

## 7. Suspend the agent

A sponsor can stop the agent with no Warden role. In Ada's terminal:

```bash
warden identity sponsor suspend teller-bot
```

It prints the entity, now in state `suspended`. The agent is refused on its next request. Its JWT is still valid, and there is no token to
revoke. In the admin terminal:

```bash
curl -s "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me" \
  -H "Authorization: Bearer $AGENT"
warden dev audit -decision deny -limit 1 -o json -F agent,entry.auth.identity_status
```

```
{"errors":["native identity (auth/agent/, teller-bot) belongs to entity \"teller-bot\", which is suspended"]}
"agent": "teller-bot",
"identity_status": "entity suspended"
```

Starting it again is an admin's write, never a sponsor's:

```bash
warden identity entity state teller-bot active
curl -s "$WARDEN_ADDR/v1/bank-api/role/teller/gateway/accounts/me" \
  -H "Authorization: Bearer $AGENT" | jq .result
```

```
| State       | active |
{ "account": "teller-bot", "balance": 1000 }
```

## What you did

- **Observed** an unregistered agent: admitted under `observe`, its roles from virtual
  groups, and `identity_status: unclaimed` in the audit log.
- **Registered** it: an entity with a description in the identity store, and a sponsor that
  a person accepted with her own ticket, signed in through the `oidc` auth method.
- **Moved** its roles to a static group first, and claimed its native identity last, so it
  never went without a role.
- **Kept** `teller` for governed agents with `governed_only`, and **required** registration
  with `deny`: an unregistered agent is refused at Resolve, and the audit log says why.
- **Stopped** the agent with one command, its sponsor's, and an admin started it again.

## Related

- [Entities](/identity/entities/): the identity store, native identities, lifecycle and `deny`.
- [Sponsors](/identity/sponsors/): proposing, accepting and handing over agents.
- [Groups](/identity/groups/): virtual groups over facts, static groups over entities.
- [Roles](/identity/roles/): roles and `governed_only`.
- [Human operators](/identity/human-operators/): `warden login`, tickets and the `oidc` mount.
- [`warden identity`](/cli/identity/) and [`warden login`](/cli/login/): the commands used here.
