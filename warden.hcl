log_format  = "standard"
log_level   = "trace"

storage "postgres" {
  connection_url = "postgres://hydra:hydrapassword@postgres-hydra:5432/hydra?sslmode=disable"
}

listener "tcp" {
    address            = ":5000"
    tls_cert_file      = "/certs/warden-cert.pem"
    tls_key_file       = "/certs/warden-key.pem"
    tls_client_ca_file = "/certs/ca.pem"
    tls_enabled        = true
}