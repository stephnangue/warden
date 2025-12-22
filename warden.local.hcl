log_format  = "standard"
log_level   = "trace"

seal "static" {
  current_key_id = "20251221-1"
  current_key = "file://./seal.key"
}

storage "file" {
  path = "./tmp/storage"
}

listener "mysql" {
    protocol           = "tcp"
    address            = "127.0.0.1:4000"
    tls_cert_file      = "./certs/warden/warden-cert.pem"
    tls_key_file       = "./certs/warden/warden-key.pem"
    tls_client_ca_file = "./certs/warden/ca.pem"
    tls_enabled        = true
}

listener "api" {
    protocol           = "tcp"
    address            = "127.0.0.1:5000"
    tls_cert_file      = "./certs/warden/warden-cert.pem"
    tls_key_file       = "./certs/warden/warden-key.pem"
    tls_client_ca_file = "./certs/warden/ca.pem"
    tls_enabled        = true
}
