log_format  = "standard"
log_level   = "trace"

listener "mysql" {
    protocol           = "tcp"
    address            = ":4000"
    tls_cert_file      = "/certs/warden-cert.pem"
    tls_key_file       = "/certs/warden-key.pem"
    tls_client_ca_file = "/certs/ca.pem"
    tls_enabled        = true
}

listener "api" {
    protocol           = "tcp"
    address            = ":5000"
    tls_cert_file      = "/certs/warden-cert.pem"
    tls_key_file       = "/certs/warden-key.pem"
    tls_client_ca_file = "/certs/ca.pem"
    tls_enabled        = true
}

