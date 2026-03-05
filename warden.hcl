log_format  = "standard"
log_level   = "trace"

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
    tls_enabled        = true
}

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