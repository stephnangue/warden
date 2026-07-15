---
title: "Dev Server"
---

The Warden dev server is a built-in, pre-configured server that is useful for
local development, testing, and exploration. With a single command you get a
running Warden that is already initialized, unsealed, and ready to accept
requests — no configuration file, no storage backend to provision, no unseal
ceremony.

The dev server is **not** suitable for production. It runs entirely in memory,
persists nothing, prints its root token to the terminal, and serves plain HTTP
on the loopback interface by default. Everything is lost when the process exits.
Use it to learn Warden, write integration tests, or prototype a provider — and
nothing else.

```
WARNING! dev mode is enabled! In this mode, Warden runs entirely
in-memory and starts automatically initialized and unsealed.
All data is lost on restart. Do NOT run dev mode in production!
```

## Starting the Dev Server

To start the dev server, run `warden server` with the `-dev` flag:

```bash
warden server -dev
```

That single command does all of the following for you:

- Selects **in-memory storage**, so nothing is written to disk.
- **Initializes** the server with a single unseal key share (1 of 1).
- **Auto-unseals** immediately using the stored key.
- Generates a **root token** and prints it to the terminal.
- Binds a TCP listener on **`127.0.0.1:8400`** with **TLS disabled**.
- Sets the log level to **`trace`** so you can see everything the server does.

Because all of this is fixed, the dev server rejects configuration that would
contradict it. You cannot combine `-dev` with `-config` or `-config-dir` —
dev mode always uses in-memory storage and its own built-in defaults.

## Dev Server Output

When the server starts, it prints a banner with everything you need to connect:

```
==> Warden server started in dev mode! <==

WARNING! dev mode is enabled! In this mode, Warden runs entirely
in-memory and starts automatically initialized and unsealed.
All data is lost on restart. Do NOT run dev mode in production!

Unseal Key 1: 6b3...e4f

Root Token: s.aBcDeFgHiJkLmNoPqRsTuVwX

Development mode should NOT be used in production installations!
```

The **Unseal Key** is printed for reference only; the dev server has already
unsealed itself with it. The **Root Token** is a fully-privileged token you use
to authenticate every request against this server.

## Connecting to the Dev Server

The dev server listens on `127.0.0.1:8400` over plain HTTP. In another terminal,
point the CLI at it by exporting `WARDEN_ADDR`:

```bash
export WARDEN_ADDR='http://127.0.0.1:8400'
```

Authenticate by exporting the root token from the startup banner:

```bash
export WARDEN_TOKEN='s.aBcDeFgHiJkLmNoPqRsTuVwX'
```

With those two variables set, the CLI talks to your dev server. Verify the
connection:

```bash
warden status
```

> **Note:** Warden does not cache tokens on disk. The dev server prints the root
> token to your terminal; you provide it to the CLI yourself by exporting
> `WARDEN_TOKEN` (or passing `-token`). The same is true in production — a token,
> mTLS client certificate, or Bearer JWT must be supplied on every request.

## Dev Server Options

The dev server accepts a handful of flags that tailor its behavior. All of them
require `-dev` and are rejected otherwise.

### Setting a known root token

By default the root token is randomly generated, which means it changes on every
restart and is awkward to script against. Use `-dev-root-token` to pin it to a
value you choose:

```bash
warden server -dev -dev-root-token=root
```

The argument may be any string. This is convenient for test fixtures and
`docker-compose` setups where a fixed, well-known token keeps configuration
simple:

```bash
export WARDEN_TOKEN='root'
warden status
```

### Serving TLS

By default the dev listener serves plain HTTP, which is safe on loopback but
differs from a real deployment. To exercise the TLS path, add `-dev-tls`:

```bash
warden server -dev -dev-tls
```

Warden generates a self-signed ECDSA P-256 certificate — valid for `localhost`,
`*.localhost`, `127.0.0.1`, and `::1` — and writes it to a temporary directory.
The banner then prints the paths and the variables needed to trust it:

```
Dev TLS Certificate:  /tmp/warden-dev-tls-1234/cert.pem
Dev TLS Private Key:  /tmp/warden-dev-tls-1234/key.pem

The certificate is self-signed, clients need to trust it:

  $ export WARDEN_CACERT=/tmp/warden-dev-tls-1234/cert.pem
  $ export WARDEN_ADDR=https://127.0.0.1:8400
```

The certificate and key are removed when the dev server shuts down.

To serve TLS with your own certificate instead of a generated one, pass the cert
and key files (which implies `-dev-tls`):

```bash
warden server -dev \
  -dev-tls-cert-file=/path/to/cert.pem \
  -dev-tls-key-file=/path/to/key.pem
```

The cert and key files must be supplied together.

### Requiring client certificates (mTLS)

To make the dev server verify client certificates, supply a CA certificate and
require its use:

```bash
warden server -dev \
  -dev-tls-ca-cert-file=/path/to/ca.pem \
  -dev-tls-require-client-cert
```

The dev server then presents its server certificate and rejects any client whose
certificate is not signed by the configured CA — a faithful local stand-in for
the mutual-TLS access pattern Warden uses in production.

### Serving a SPIFFE identity

Warden's dev server can present a **SPIFFE Workload API X.509-SVID** instead of a
static or self-signed certificate. This lets you develop against an
auto-rotating workload identity with no private key written to disk:

```bash
warden server -dev -dev-tls-spiffe
```

By default the Workload API socket is taken from the `SPIFFE_ENDPOINT_SOCKET`
environment variable. Override it explicitly with `-dev-tls-spiffe-socket`:

```bash
warden server -dev -dev-tls-spiffe-socket=unix:///tmp/agent.sock
```

When SPIFFE dev TLS is active the banner notes the source:

```
Dev TLS Source: SPIFFE Workload API (auto-rotating SVID, no key on disk)

The server presents a SPIFFE SVID; clients must be SPIFFE-aware
(trust the SPIRE bundle and skip hostname verification).
```

The Workload API must be reachable at startup; if it is not, the dev server
fails to start rather than falling back to an insecure listener. SPIFFE dev TLS
is mutually exclusive with the file-based `-dev-tls-*` certificate flags.

## Flag Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-dev` | `false` | Enable dev mode: in-memory storage, auto-init, auto-unseal. |
| `-dev-root-token` | _(random)_ | Use a custom root token instead of a generated one. Any string. |
| `-dev-tls` | `false` | Serve TLS on the dev listener, auto-generating a self-signed certificate. |
| `-dev-tls-cert-file` | _(none)_ | Serve TLS using this certificate file. Implies `-dev-tls`; requires `-dev-tls-key-file`. |
| `-dev-tls-key-file` | _(none)_ | Private key matching `-dev-tls-cert-file`. |
| `-dev-tls-ca-cert-file` | _(none)_ | CA certificate used to verify client certificates. |
| `-dev-tls-require-client-cert` | `false` | Require a client certificate signed by `-dev-tls-ca-cert-file`. |
| `-dev-tls-spiffe` | `false` | Serve TLS using an auto-rotating SPIFFE Workload API X.509-SVID. |
| `-dev-tls-spiffe-socket` | `$SPIFFE_ENDPOINT_SOCKET` | Workload API socket for `-dev-tls-spiffe`. |

## Environment Variables

The CLI and any Warden API client read their configuration from `WARDEN_`-prefixed
environment variables. The ones you need for the dev server are:

| Variable | Purpose |
|----------|---------|
| `WARDEN_ADDR` | Server address, e.g. `http://127.0.0.1:8400` (or `https://...` under `-dev-tls`). |
| `WARDEN_TOKEN` | Token used to authenticate requests — the dev root token. |
| `WARDEN_CACERT` | Path to a CA certificate to trust, used with `-dev-tls`. |

## What the Dev Server Does Not Do

The dev server is deliberately minimal. Knowing what it leaves out helps explain
behavior you might otherwise find surprising:

- **No persistence.** Storage is in memory. Every provider you enable, policy you
  write, and secret you create is gone the moment the process exits.
- **No audit devices.** The dev server ships with zero audit devices enabled. If
  your workflow depends on audit log output, enable an audit device explicitly
  after startup.
- **No automatic mounts.** Warden does not pre-mount any providers or auth
  methods in dev mode. Enable the ones you need yourself.
- **No real seal.** The barrier is auto-unsealed from an in-memory key; there is
  no Shamir ceremony, KMS, or recovery process to exercise.

When you are ready to move beyond experimentation, see the
[Architecture](/architecture/) overview and the
[Kubernetes install guide](/install/kubernetes/) for storage, seal, high
availability, and audit configuration.
