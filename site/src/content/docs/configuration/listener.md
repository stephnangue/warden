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
| `trusted_proxies` | *(none)* | CIDR ranges of load balancers permitted to forward the client certificate (for LB cert forwarding). |

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

## See Also

- [SPIFFE auth method](/auth-methods/spiffe/) — authenticating peers by SVID.
- [Certificate auth method](/auth-methods/cert/) — authenticating peers by client certificate.
- [`warden server`](/cli/server/) — the dev-mode TLS flags for local work.
