log_format  = "standard"
log_level   = "trace"

min_cred_source_rotation_period = "5m"
min_cred_spec_rotation_period   = "5m"

ip_binding_policy = "optional"

seal "static" {
  current_key_id = "20251221-1"
  current_key = "file://./seal.key"
}

storage "postgres" {
  connection_url = "postgres://warden:wardenpassword@localhost:5433/warden?sslmode=disable"
}

listener "tcp" {
    address            = "127.0.0.1:8400"
    tls_cert_file      = "./certs/warden/warden-cert.pem"
    tls_key_file       = "./certs/warden/warden-key.pem"
    tls_client_ca_file = "./certs/warden/ca.pem"
    tls_enabled        = true
}

