---
title: "Listener"
---

> Server config stanza: `listener "<type>"`

A `listener` stanza declares where the server accepts API traffic and how it
secures the connection. The stanza may be repeated to serve on more than one
address — for example a file-based TLS listener for browser clients alongside a
[SPIFFE](#spiffe-serving-identity) listener for workloads.

```hcl
listener "tcp" {
  address       = ":8400"
  tls_cert_file = "/certs/warden-cert.pem"
  tls_key_file  = "/certs/warden-key.pem"
}
```

The type label is `tcp` or `unix`.

## TLS is on by default

Warden serves TLS unless you explicitly opt out. A file-based listener must
therefore either provide both `tls_cert_file` and `tls_key_file`, or set
`tls_disable = true` — the server refuses to start otherwise. Disabling TLS is
only appropriate behind a trusted terminating proxy or on a loopback address.

| Key | Default | Description |
|-----|---------|-------------|
| `address` | *(required)* | Bind address, e.g. `:8400`, `127.0.0.1:8400`, or a socket path for `unix`. |
| `tls_cert_file` | *(none)* | PEM certificate (chain) to serve. Required unless `tls_disable` or `tls_spiffe`. |
| `tls_key_file` | *(none)* | PEM private key paired with the certificate. |
| `tls_client_ca_file` | *(none)* | CA bundle used to verify client certificates for mTLS. |
| `tls_disable` | `false` | Serve plaintext HTTP instead of TLS. Mutually exclusive with the TLS keys. |
| `tls_require_client_cert` | *(true when `tls_client_ca_file` is set)* | Require and verify a client certificate. |
| `trusted_proxies` | *(none)* | CIDR ranges of load balancers whose forwarding headers Warden believes — the client certificate, client IP and request id. See [Trusted proxies](#trusted-proxies). |

## Trusted proxies

A load balancer in front of Warden speaks for the client through forwarding headers.
Warden believes those headers **only from a connection whose address is in
`trusted_proxies`**; from anyone else it ignores them, so a caller cannot choose the IP it
is matched against or the identity it is logged as.

```hcl
listener "tcp" {
  address         = ":8400"
  tls_cert_file   = "/certs/warden-cert.pem"
  tls_key_file    = "/certs/warden-key.pem"
  trusted_proxies = ["10.0.0.0/24"]
}
```

| From a trusted proxy | Warden takes |
|---|---|
| `X-Forwarded-For` | The client IP: the rightmost entry that is not itself a trusted proxy, or the leftmost when every entry is. Entries further left are whatever the client sent. |
| `X-Real-IP` | The client IP, when there is no `X-Forwarded-For`. |
| `X-Request-Id` | The request id recorded in the audit log, when it is a plausible id. |
| `X-Forwarded-Client-Cert`, `X-SSL-Client-Cert` | The client certificate, for [cert auth](/auth-methods/cert/). |

From any other connection, the client IP is the connection's own address, the request id
is a new one, and the certificate headers are stripped; a certificate from the TLS
handshake itself — a direct mTLS client, or a balancer in TLS passthrough — still counts.

:::caution[Behind a load balancer, list it]
Without the entry, every request's client IP is the **balancer's** address. That is the
IP a token's IP binding checks and the `request.client_ip` a
[policy condition](/concepts/cel-conditions/#19-source-ip-allowlist) sees. Before v0.21.0,
`trusted_proxies` governed only the forwarded client certificate. See
[Upgrading from v0.20.0](/upgrade/from-v0-20/).
:::

## SPIFFE serving identity

Instead of a certificate and key on disk, a listener can source its serving
certificate from the **SPIFFE Workload API** (a local SPIRE agent). The X509-SVID
is held in memory and fetched fresh on every TLS handshake, so it rotates
transparently and no key or certificate is ever written to disk.

```hcl
listener "tcp" {
  address    = ":8400"
  tls_spiffe = true

  # Workload API endpoint. Omit to use the SPIFFE_ENDPOINT_SOCKET env var.
  # tls_spiffe_socket = "unix:///run/spire/agent/sockets/agent.sock"

  # Max time to wait (and retry) for the first SVID at startup before failing
  # closed. Tolerates a brief agent-not-ready window at boot.
  # tls_spiffe_startup_timeout = "10s"
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `tls_spiffe` | `false` | Serve using a SPIFFE Workload API X509-SVID instead of file-based certs. |
| `tls_spiffe_socket` | `$SPIFFE_ENDPOINT_SOCKET` | Workload API endpoint. |
| `tls_spiffe_startup_timeout` | `10s` | Max wait/retry for the first SVID at boot before failing closed. |

`tls_spiffe` is **mutually exclusive** with `tls_cert_file`, `tls_key_file`,
`tls_client_ca_file`, and `tls_require_client_cert`. A SPIFFE listener always
requests and captures the peer's certificate but never verifies it at the TLS
layer — the [SPIFFE](/auth-methods/spiffe/) or [cert](/auth-methods/cert/) auth
method authenticates the peer instead, so clients that authenticate by token (or
present no certificate) still connect.

The server presents a SPIFFE SVID (a `spiffe://` URI SAN with no DNS SAN), so
clients must be SPIFFE-aware — they trust the SPIRE bundle and skip hostname
verification. Plain or browser clients cannot use a SPIFFE listener; run a
separate file-based listener on another port for those.

## HTTP timeouts

Three keys bound how long the server will wait on a connection:

| Key | Default | Bounds |
|---|---|---|
| `http_read_timeout` | `5s` | Reading the request, headers and body. |
| `http_write_timeout` | `10s` | Writing the response. |
| `http_idle_timeout` | `1m` | An idle keep-alive connection before it is closed. |

```hcl
listener "tcp" {
  address            = ":8400"
  http_write_timeout = "30s"
}
```

**Streaming and gateway traffic sheds these deadlines**, and so does the standby
forwarder. A proxied provider call is bounded by the mount's own `timeout` instead — see
[Provider configuration](/provider-backends/configuration/) — because the right budget for
an LLM completion or a long MCP tool call has nothing to do with the right budget for a
`sys/` API call.

:::note[New in v0.20.0]
These were hardcoded before. `http_write_timeout` in particular was fixed at 10 seconds,
which severed **every** response that took longer — no LLM provider mount could reach its
120-second budget, and raising the mount `timeout` did nothing because the listener cut the
connection first. See [Upgrading from v0.19.0](/upgrade/from-v0-19/).
:::

## See Also

- [SPIFFE auth method](/auth-methods/spiffe/) — authenticating peers by SVID.
- [Certificate auth method](/auth-methods/cert/) — authenticating peers by client certificate.
- [`warden server`](/cli/server/) — the dev-mode TLS flags for local work.
