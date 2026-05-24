log_format  = "standard"
log_level   = "trace"

min_cred_source_rotation_period = "5m"
min_cred_spec_rotation_period   = "5m"

ip_binding_policy = "optional"

api_addr     = "https://127.0.0.1:8400"
cluster_addr = "https://127.0.0.1:8401"

seal "static" {
  current_key_id = "20251221-1"
  current_key = "file://./seal.key"
}

storage "postgres" {
  connection_url = "postgres://warden:wardenpassword@localhost:5433/warden?sslmode=disable"
  ha_enabled     = "true"
}

listener "tcp" {
    address                 = "127.0.0.1:8400"
    tls_cert_file           = "./certs/warden/warden-cert.pem"
    tls_key_file            = "./certs/warden/warden-key.pem"
    tls_client_ca_file      = "./certs/warden/ca.pem"
    tls_require_client_cert = false
}

listener "tcp" {
    address     = "127.0.0.1:8500"
    tls_disable = true
}

# Audit "TYPE" "NAME" — registered at startup, before the listener accepts
# traffic. Uncomment for a local file sink, or leave off and let the broker
# fail-open (zero declared = no audit; `warden audit enable file ...`
# bootstraps one over the API).

# audit "file" "local" {
#   description = "local-dev file audit"
#   options = {
#     file_path = "./warden-audit.log"
#   }
# }

