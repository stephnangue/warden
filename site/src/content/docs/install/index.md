---
title: "Install Warden"
description: "Install the Warden binary, run it in Docker, or deploy it to Kubernetes with the first-party Helm chart."
sidebar:
  label: Overview
  order: 1
---

Warden ships as a single static binary that is both the command-line client and
the server. Installing it is the same act either way — what differs is where you
want the server to run.

## Quick install

macOS and Linux, amd64 or arm64:

```bash
curl -sL https://wardengateway.com/install.sh | bash
```

Windows has no install script — see [Binary](/install/binary/#windows).

:::note[What the script does]
It resolves the latest release, downloads the archive for your platform, and
installs `warden` into the first of `~/.local/bin`, `/opt/homebrew/bin`,
`/usr/local/bin`, `~/bin` that exists, is writable, and is already on your
`PATH` — falling back to `~/.local/bin` when none qualifies. Override the
destination with `WARDEN_INSTALL_DIR`. Whenever the destination is not already
on your `PATH`, the script appends it to your shell profile and tells you so.

It is plain bash and short enough to read before you run it:

```bash
curl -sL https://wardengateway.com/install.sh | less
```
:::

## Verify

```bash
warden --version
warden --help
```

If `--version` prints `dev`, you are running a build made outside the release
pipeline — see [Building from source](/install/binary/#building-from-source).

## Pick your path

| Path | Choose this when |
|---|---|
| **[Binary](/install/binary/)** | You want `warden` on a laptop, a VM, or a CI runner — the client you use against every Warden, and a server for local testing. macOS, Linux, Windows. |
| **[Docker](/install/docker/)** | You want a throwaway server with nothing on your `PATH`, or you already run a Compose stack. |
| **[Helm](/install/helm/)** | You deploy with Helm and want the chart reference: install methods, values, versioning, upgrades, and rollback. |
| **[Kubernetes](/install/kubernetes/)** | You want the end-to-end production deployment: PostgreSQL, TLS, Transit auto-unseal, first-time initialization, and day-2 runbooks. |

## Dev mode or a real deployment?

**Dev mode** is one command and no configuration:

```bash
warden server -dev -dev-root-token=root
```

Storage is in-memory, the cluster initializes and unseals itself, and the
listener is plain HTTP on `127.0.0.1:8400`. Everything is lost when the process
exits. That is the right tool for a tutorial, a demo, or a local agent
experiment — see [Dev Server](/concepts/dev-server/).

**A real deployment** needs four things dev mode fakes:

- a PostgreSQL [storage backend](/configuration/storage/) — the only backend that supports HA
- a TLS [listener](/configuration/listener/) — Warden requires TLS on the API port
- a [seal](/concepts/seal-unseal/), so the barrier key is never at rest in the clear
- a one-time `warden operator init` to generate the root token and unseal keys

Configuration is [HCL](/configuration/). Warden listens on **8400** for the API
and **8401** for inter-node forwarding between cluster members.

## Next steps

- [Quickstarts](/quickstarts/workstation/) — put an agent behind Warden on your own machine
- [Concepts](/concepts/) — roles, policies, credentials, delegation
- [CLI reference](/cli/)
