---
title: "login"
---

Sign in as a person. `warden login` opens your identity provider in the
browser through the namespace's [oidc](/auth-methods/oidc/) auth mount, saves
the session Warden issues (a [ticket](/identity/tokens/#tickets)), and chooses
the role the commands that follow run under. See
[Human operators](/identity/human-operators/) for the model and the mount's
setup.

## Usage

```text
warden login [options]
warden logout
warden print token
```

Global flags apply to every command — see the [CLI overview](/cli/#global-flags).

## Commands

| Command | Description |
|---|---|
| `login` | Sign in with your identity provider and choose a role. |
| `logout` | Forget the session of the current Warden address and namespace. |
| `print token` | Print the session token of the current Warden address and namespace. |
| [`role use [name]`](/cli/role/) | Choose the role commands run under in the current session, without signing in again. |

### `login`

Sign in through the oidc auth mount of the current namespace. The browser opens
at your identity provider; once you have signed in, Warden issues a session,
valid for the mount's `session_ttl`. The session is saved and used by the
`warden` commands that follow.

Then `warden login` lists the roles your groups grant you and lets you choose
one (arrows to move, type to filter, Enter to select):

- with `-role` (or `WARDEN_ROLE`), that role is checked and chosen without
  asking;
- with one role, it is chosen for you;
- with several and no terminal, the roles are listed on stderr and none is
  chosen: pick one with `warden role use <name>`.

Switch later with [`warden role use`](/cli/role/).

**Usage:** `warden login [options]`

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `-path` | `oidc` | Path of the auth mount, under `auth/`. Defaults to the method's name. |
| `-method` | `oidc` | Auth method to sign in with. `oidc` is the one interactive method; any other value is refused. |
| `-callback-port` | `8251` | Port of the sign-in redirect, `http://localhost:<port>/oidc/callback`. `0` picks a free one. |
| `-no-browser` | `false` | Print the sign-in URL instead of opening a browser. |
| `-no-store` | `false` | Print the session token on stdout instead of saving the session. |
| `-timeout` | `5m` | How long to wait for the sign-in to finish in the browser. |
| `-force` | `false` | Sign in again even when a session of this namespace and mount is still valid. |

The global `-role` (`-r`, or `WARDEN_ROLE`) names the role to choose, and
`-namespace` (`-n`, or `WARDEN_NAMESPACE`) signs you in to that namespace's
mount.

**Examples:**

```bash
warden login
warden login -path=oidc-prod
warden login -role=operator
warden login -n team-a
warden login -no-browser
warden login -callback-port=9000
warden login -force
```

**The redirect.** The identity provider sends the browser back to
`http://localhost:8251/oidc/callback`, where the CLI listens on the loopback
addresses for the duration of the sign-in. Register that redirect URI at the
provider (see [OIDC auth method](/auth-methods/oidc/)). `-callback-port`
changes the port; `-callback-port=0` picks a free one, for a provider that
accepts any loopback port. A port already in use is refused with a message
naming `-callback-port`.

**Keeping a session.** A session of the same namespace and mount with more than
5 minutes left, which the server still accepts, is kept: there is no new
sign-in, and only the role `-role` names, if any, is applied. A parent
namespace's session does not count here, since this namespace's mount was
asked for. `-force` signs in again. That is how a change to your groups at the
identity provider reaches the session: its claims are fixed when it is issued.

```bash
warden login -force
```

**Without saving.** `-no-store` always signs in, prints the session token on
stdout, and saves nothing, for a tool that keeps the token itself. The role
chosen is not saved either.

While it signs in, `warden login` sends no credential: a `WARDEN_TOKEN` in the
environment is not used.

### `logout`

Delete the session `warden login` saved for the current Warden address and
namespace or, when the namespace has none, the nearest parent's, which is the
one commands use there. A session file that cannot be read is removed too.

The session token itself stays valid until it expires: a session cannot be
revoked before then. Disabling its auth mount ends every session it issued.

**Usage:** `warden logout`

```bash
warden logout
```

### `print token`

Print the session token of the current Warden address and namespace (or the
nearest parent's) on stdout, for other tools. It fails when there is no
session or it has expired; run `warden login`.

**Usage:** `warden print token`

```bash
curl -H "Authorization: Bearer $(warden print token)" "$WARDEN_ADDR/v1/sys/introspect/roles"
```

The token carries no role. Name one the way the path asks for one, such as
the `X-Warden-Role` header on Warden's own API:

```bash
curl -H "Authorization: Bearer $(warden print token)" \
     -H "X-Warden-Role: warden-viewer" \
     "$WARDEN_ADDR/v1/sys/roles?warden-list=true"
```

## The session on your machine

Sessions are kept in `~/.warden/sessions` (mode `0700`), one `0600` file per
Warden address and namespace, so several clusters and namespaces coexist. Each
file holds the session token, the mount that issued it, its expiry, and the
role chosen with `warden login` or `warden role use`.

- **Credential.** When `WARDEN_TOKEN` or `WARDEN_CLIENT_CERT` is set, no
  session is sent at all.
- **Role.** `-role`, then `WARDEN_ROLE`, then the session's role. The session's
  role is sent only with the session token.
- **Namespaces.** In a namespace with no session of its own, commands use the
  nearest parent's (`team-a/dev`, then `team-a`, then the root), never a
  sibling's or a child's, and say so on stderr:
  `using session from namespace …`.
- **Expiry.** An expired session is not sent. The command runs without it,
  after a notice: `session expired; run warden login`.

## See Also

- [Human operators](/identity/human-operators/) — sign-in, tickets, and roles for people.
- [OIDC auth method](/auth-methods/oidc/) — registering Warden at your identity provider.
- [Tokens](/identity/tokens/) — tickets beside the other token kinds.
- [role](/cli/role/) — `warden role use` and the roles you can assume.
- [identity](/cli/identity/) — the sponsor commands a session reaches.
- [CLI overview](/cli/) — global flags, output formats, exit codes.
