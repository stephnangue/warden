---
title: "dev"
description: "Mint playground identities, read the playground's audit log, and print its tour."
---

Commands for the playground started by `warden server -dev-playground`. They mint the
identities the tour's agents and people present, read what the audit log recorded, and
print the tour in the terminal. Every subcommand needs the dev server's **root token**
in `WARDEN_TOKEN`. The paths behind them exist only on a server started with
`-dev-playground`; any other server answers that it has no such path.

The tour itself is on [Getting started](/getting-started/), written out for each agent.

## Usage

```text
warden dev <subcommand> [options]
```

Global flags apply to every subcommand — see the [CLI overview](/cli/#global-flags).

## Subcommands

| Subcommand | Description |
|---|---|
| `jwt` | Mint an agent or user identity signed by the playground's identity provider. |
| `audit` | Show what the playground's audit log recorded. |
| `scenarios` | Print the tour in the terminal. |

## jwt

```text
warden dev jwt <agent|user> <sub> [options]
```

Mints a JWT from the playground's identity provider. An agent presents its own; a
user's is presented alongside an agent's when the agent acts for them. The token is
printed bare, so it can be captured:

```bash
AGENT=$(warden dev jwt agent agent-1) &&
ALICE=$(warden dev jwt user alice -may-act agent-1) &&
BOB=$(warden dev jwt user bob -may-act agent-1 -claims '{"tier": "premium"}' -ttl 8h)
```

| Flag | Default | Description |
|---|---|---|
| `-may-act` | *(none)* | For a user: the agent allowed to act for them, carried as the `may_act` claim the playground's policy checks. |
| `-ttl` | `1h` | Lifetime of the token, at most `24h`. |
| `-claims` | *(none)* | Extra claims, as a JSON object. |
| `-json` | *(none)* | The whole request as JSON — inline, `@file`, or `-` for stdin. Cannot be combined with arguments or the other flags. |

The whole request as JSON:

```bash
warden dev jwt -json '{
  "kind": "user",
  "sub": "alice",
  "may_act": { "sub": "agent-1" },
  "ttl": "1h"
}'
```

With `-o json`, the token is printed with its decoded claims. `WARDEN_OUTPUT` does
not change this command's output, so `$(…)` always captures the bare token.

## audit

```text
warden dev audit [options]
```

Reads the playground's audit log, newest first: who called, under which role, for
which person, which tool, and what Warden decided.

```bash
warden dev audit -decision deny
warden dev audit -user alice -limit 5
warden dev audit -role-name assistant
```

| Flag | Default | Description |
|---|---|---|
| `-limit` | `20` | How many entries, newest first. At most `1000`. |
| `-principal` | *(none)* | Only calls made by this agent. |
| `-user` | *(none)* | Only calls made for this user. |
| `-role-name` | *(none)* | Only calls made under this role. Named so, not `-role`, which is the global role flag. |
| `-decision` | *(none)* | Only `allow` or `deny`. |

## scenarios

```text
warden dev scenarios [N] [options]
```

Prints the tour Getting started writes out — the setup, then each scenario's
commands, what to ask the agent, and what to look for — built for this server's
address. `N` prints one scenario, still knowing which servers the scenarios before
it connected the agent to.

| Flag | Default | Description |
|---|---|---|
| `-client` | `claude` | The agent to print commands for: `claude`, `codex`, `cursor`, `gemini`, `opencode`, `vscode`, or `generic` for the URL and headers to enter in any other. `WARDEN_DEV_CLIENT` sets it once. |

With `-o json`, the scenarios are printed as data.

## See Also

- [Getting started](/getting-started/) — the playground's tour.
- [Dev Server](/concepts/dev-server/) — what dev mode and the playground set up.
- [`server`](/cli/server/) — the `-dev-playground` flags.
