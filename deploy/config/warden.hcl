log_format  = "standard"
log_level   = "trace"

# Config values may reference environment variables using Go template syntax,
# e.g. {{ env "POD_NAME" }}. Missing variables expand to the empty string.
# This is useful in Kubernetes where each pod advertises a unique address:
#
#   api_addr     = "https://{{ env "POD_NAME" }}.warden-headless.{{ env "POD_NAMESPACE" }}.svc.cluster.local:8400"
#   cluster_addr = "https://{{ env "POD_NAME" }}.warden-headless.{{ env "POD_NAMESPACE" }}.svc.cluster.local:8401"
#
# HCL's own ${...} interpolation syntax is left untouched.

# api_addr is the address advertised to clients for API requests.
# Required when ha_enabled = "true".
# api_addr = "https://warden.example.com:8400"

# cluster_addr is the address used for inter-node cluster communication.
# A dedicated cluster listener is started on this address with
# auto-generated mTLS certificates (no external certs needed).
# Required when ha_enabled = "true".
# cluster_addr = "https://warden.example.com:8401"

storage "postgres" {
  connection_url = "postgres://hydra:hydrapassword@postgres-hydra:5432/hydra?sslmode=disable"
}

listener "tcp" {
    address            = ":8400"
    tls_cert_file      = "/certs/warden-cert.pem"
    tls_key_file       = "/certs/warden-key.pem"
    tls_client_ca_file = "/certs/ca.pem"
    tls_require_client_cert = false
}

# --- SPIFFE serving identity (alternative to file-based TLS) -----------------
#
# Instead of tls_cert_file/tls_key_file, a listener can source its serving
# certificate from the SPIFFE Workload API (a local SPIRE agent). The X509-SVID
# is kept in memory and fetched fresh on every TLS handshake, so it rotates
# transparently and no key or cert is ever written to disk.
#
# tls_spiffe is mutually exclusive with tls_cert_file / tls_key_file /
# tls_client_ca_file / tls_require_client_cert. The listener always requests and
# captures the client's certificate but never verifies it at the TLS layer —
# the SPIFFE/cert auth method authenticates the peer SVID against its configured
# trust domains. RequestClientCert only *requests* a cert, so clients that
# authenticate by token (or present no cert) connect normally.
#
# Note: the server presents a SPIFFE SVID (a spiffe:// URI SAN, no DNS SAN), so
# clients must be SPIFFE-aware (trust the SPIRE bundle and skip hostname
# verification). Plain/browser clients cannot use a SPIFFE listener — run a
# separate file-based listener on another port for those.
#
# listener "tcp" {
#   address    = ":8400"
#   tls_spiffe = true
#
#   # Workload API endpoint. Omit to use the SPIFFE_ENDPOINT_SOCKET env var.
#   # tls_spiffe_socket = "unix:///run/spire/agent/sockets/agent.sock"
#
#   # Max time to wait (and retry) for the first SVID at startup before failing
#   # closed. Tolerates a brief agent-not-ready window at boot. Default "10s".
#   # tls_spiffe_startup_timeout = "10s"
# }

# Audit devices are declared with the two-label syntax:
#   audit "TYPE" "NAME" { description = "..." options = { ... } }
#
# Devices declared here are registered at startup BEFORE the API
# listener accepts traffic. A misconfigured sink (unwritable path,
# missing parent directory, permission denied) fails startup instead
# of leaving a half-initialized cluster.
#
# Declared and API-enabled (via sys/audit/{path}) devices coexist at
# different paths. A device declared here cannot be modified or
# deleted via the API — edit this file and restart instead.
#
# With zero audit devices the broker fail-opens (so a fresh cluster
# can serve sys/audit/{path} long enough to bootstrap one), but ≥ 2
# devices are recommended in production to avoid lockout if a single
# sink wedges.
#
# All values inside `options = { ... }` are strings (HCL limitation
# in this version). Non-string knobs like rotate_size and rotate_daily
# should be tuned through the sys/audit/{path} API for now.

# audit "file" "default" {
#   description = "primary file audit"
#   options = {
#     file_path = "/var/log/warden/audit.log"
#   }
# }

# IP binding policy controls how client IP validation is enforced for tokens.
# Options:
#   - "disabled": No IP binding checks
#   - "optional": Check only if both creation and request IPs are present (default)
#   - "required": Reject tokens without IP binding or requests without client IP
# ip_binding_policy = "optional"

# HA cluster tuning
# All values are Go duration strings (e.g., "30s", "5m", "1h").
# Omitted values use built-in defaults.

# Max time to wait for background goroutines to exit during step-down.
# goroutine_shutdown_timeout = "30s"

# Max time to wait when acquiring the HA lock. "0" means wait indefinitely.
# lock_acquisition_timeout = "0"

# How often the active node cleans stale leader advertisements from storage.
# leader_cleanup_interval = "1h"

# Max time to acquire the state lock during step-down before forcing teardown.
# step_down_state_lock_timeout = "30s"

# Deadline for barrier reads when looking up the leader advertisement.
# leader_lookup_timeout = "10s"

# Backwards offset on cluster certificate NotBefore to tolerate clock drift.
# clock_skew_grace = "1m"

# HTTP read timeout for the cluster listener (inter-node forwarding).
# cluster_listener_read_timeout = "30s"

# HTTP write timeout for the cluster listener.
# cluster_listener_write_timeout = "1m"

# Max time for a forwarded request from standby to active node.
# forwarding_timeout = "1m"