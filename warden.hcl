log_format  = "standard"
log_level   = "trace"

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