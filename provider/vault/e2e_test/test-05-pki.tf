# test-05-pki.tf
# Tests 61-75: PKI Secrets Engine
# Tests: CA setup, certificate issuance, CRL, OCSP

################################################################################
# PKI Secrets Engine Mount - Root CA
################################################################################
resource "vault_mount" "pki_root" {
  path        = "${local.name_prefix}-pki-root"
  type        = "pki"
  description = "Root CA for Warden testing"

  default_lease_ttl_seconds = 86400      # 1 day
  max_lease_ttl_seconds     = 315360000  # 10 years
}

################################################################################
# PKI Secrets Engine Mount - Intermediate CA
################################################################################
resource "vault_mount" "pki_int" {
  path        = "${local.name_prefix}-pki-int"
  type        = "pki"
  description = "Intermediate CA for Warden testing"

  default_lease_ttl_seconds = 86400     # 1 day
  max_lease_ttl_seconds     = 157680000 # 5 years
}

################################################################################
# Test 61: Generate Root CA
################################################################################
resource "vault_pki_secret_backend_root_cert" "root" {
  backend     = vault_mount.pki_root.path
  type        = "internal"
  common_name = "Warden Test Root CA"
  ttl         = "315360000" # 10 years
  format      = "pem"

  key_type   = "rsa"
  key_bits   = 4096

  organization        = "Warden Test Organization"
  ou                  = "PKI Testing"
  country             = "US"
  province            = "California"
  locality            = "San Francisco"

  issuer_name = "root-ca"
}

################################################################################
# Test 62: Configure Root CA URLs
################################################################################
resource "vault_pki_secret_backend_config_urls" "root" {
  backend = vault_mount.pki_root.path

  issuing_certificates    = ["http://vault.example.com:8200/v1/${vault_mount.pki_root.path}/ca"]
  crl_distribution_points = ["http://vault.example.com:8200/v1/${vault_mount.pki_root.path}/crl"]
}

################################################################################
# Test 63: Generate Intermediate CA CSR
################################################################################
resource "vault_pki_secret_backend_intermediate_cert_request" "int" {
  backend     = vault_mount.pki_int.path
  type        = "internal"
  common_name = "Warden Test Intermediate CA"

  key_type   = "rsa"
  key_bits   = 4096

  organization = "Warden Test Organization"
  ou           = "PKI Testing"
  country      = "US"
  province     = "California"
  locality     = "San Francisco"
}

################################################################################
# Test 64: Sign Intermediate CA with Root CA
################################################################################
resource "vault_pki_secret_backend_root_sign_intermediate" "int" {
  backend     = vault_mount.pki_root.path
  common_name = "Warden Test Intermediate CA"
  csr         = vault_pki_secret_backend_intermediate_cert_request.int.csr
  ttl         = "157680000" # 5 years
  format      = "pem_bundle"

  organization = "Warden Test Organization"
  ou           = "PKI Testing"
  country      = "US"
  province     = "California"
  locality     = "San Francisco"
}

################################################################################
# Test 65: Set Signed Intermediate Certificate
################################################################################
resource "vault_pki_secret_backend_intermediate_set_signed" "int" {
  backend     = vault_mount.pki_int.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.int.certificate
}

################################################################################
# Test 66: Configure Intermediate CA URLs
################################################################################
resource "vault_pki_secret_backend_config_urls" "int" {
  backend = vault_mount.pki_int.path

  issuing_certificates    = ["http://vault.example.com:8200/v1/${vault_mount.pki_int.path}/ca"]
  crl_distribution_points = ["http://vault.example.com:8200/v1/${vault_mount.pki_int.path}/crl"]
  ocsp_servers            = ["http://vault.example.com:8200/v1/${vault_mount.pki_int.path}/ocsp"]
}

################################################################################
# Test 67: PKI Role - Server Certificates
################################################################################
resource "vault_pki_secret_backend_role" "server" {
  backend = vault_mount.pki_int.path
  name    = "server-cert"

  ttl      = "86400"   # 1 day default
  max_ttl  = "2592000" # 30 days max

  allow_localhost    = true
  allowed_domains    = ["example.com", "internal.example.com", "warden.local"]
  allow_subdomains   = true
  allow_glob_domains = true
  allow_any_name     = false
  allow_ip_sans      = true
  allow_bare_domains = false

  server_flag = true
  client_flag = false

  key_type  = "rsa"
  key_bits  = 2048
  key_usage = ["DigitalSignature", "KeyEncipherment"]

  organization        = ["Warden Test Organization"]
  ou                  = ["Server Certificates"]
  country             = ["US"]
  province            = ["California"]
  locality            = ["San Francisco"]

  require_cn         = true
  use_csr_common_name = true
  use_csr_sans       = true

  no_store = false
}

################################################################################
# Test 68: PKI Role - Client Certificates
################################################################################
resource "vault_pki_secret_backend_role" "client" {
  backend = vault_mount.pki_int.path
  name    = "client-cert"

  ttl      = "43200"   # 12 hours default
  max_ttl  = "604800"  # 7 days max

  allow_any_name   = true
  enforce_hostnames = false

  server_flag = false
  client_flag = true

  key_type  = "rsa"
  key_bits  = 2048
  key_usage = ["DigitalSignature"]
  ext_key_usage = ["ClientAuth"]

  organization = ["Warden Test Organization"]
  ou           = ["Client Certificates"]
  country      = ["US"]

  require_cn = true
  no_store   = false
}

################################################################################
# Test 69: PKI Role - Wildcard Certificates
################################################################################
resource "vault_pki_secret_backend_role" "wildcard" {
  backend = vault_mount.pki_int.path
  name    = "wildcard-cert"

  ttl     = "604800"  # 7 days
  max_ttl = "2592000" # 30 days

  allowed_domains  = ["example.com", "internal.example.com"]
  allow_subdomains = true
  allow_wildcard_certificates = true
  allow_bare_domains = false

  server_flag = true
  client_flag = false

  key_type = "rsa"
  key_bits = 2048

  no_store = false
}

################################################################################
# Test 70: PKI Role - Short-lived Certificates
################################################################################
resource "vault_pki_secret_backend_role" "short_lived" {
  backend = vault_mount.pki_int.path
  name    = "short-lived-cert"

  ttl     = "3600"   # 1 hour default
  max_ttl = "86400"  # 24 hours max

  allow_any_name = true

  server_flag = true
  client_flag = true

  key_type = "ec"
  key_bits = 256

  # Don't store for efficiency
  no_store          = true
  generate_lease    = false
}

################################################################################
# Test 71: PKI Role - Service Mesh (mTLS)
################################################################################
resource "vault_pki_secret_backend_role" "service_mesh" {
  backend = vault_mount.pki_int.path
  name    = "service-mesh"

  ttl     = "3600"    # 1 hour
  max_ttl = "86400"   # 24 hours

  allowed_domains    = ["svc.cluster.local", "service.consul"]
  allow_subdomains   = true
  allow_bare_domains = true
  allow_ip_sans      = true

  # Both server and client for mTLS
  server_flag = true
  client_flag = true

  key_type = "ec"
  key_bits = 256

  # SPIFFE ID support
  allowed_uri_sans = ["spiffe://*"]

  ext_key_usage = ["ServerAuth", "ClientAuth"]

  no_store       = true
  generate_lease = false
}

################################################################################
# Test 72: Issue Server Certificate
################################################################################
resource "vault_pki_secret_backend_cert" "server_example" {
  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]

  backend     = vault_mount.pki_int.path
  name        = vault_pki_secret_backend_role.server.name
  common_name = "api.example.com"

  alt_names = ["api-v2.example.com", "api.internal.example.com"]
  ip_sans   = ["10.0.0.1", "192.168.1.1"]

  ttl            = "86400"
  auto_renew     = true
  min_seconds_remaining = 3600

  revoke = false
}

################################################################################
# Test 73: Issue Client Certificate
################################################################################
resource "vault_pki_secret_backend_cert" "client_example" {
  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]

  backend     = vault_mount.pki_int.path
  name        = vault_pki_secret_backend_role.client.name
  common_name = "service-account@example.com"

  ttl            = "43200"
  auto_renew     = true
  min_seconds_remaining = 3600

  revoke = false
}

################################################################################
# Test 74: Issue Wildcard Certificate
################################################################################
resource "vault_pki_secret_backend_cert" "wildcard_example" {
  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]

  backend     = vault_mount.pki_int.path
  name        = vault_pki_secret_backend_role.wildcard.name
  common_name = "*.example.com"

  ttl            = "604800"
  auto_renew     = true
  min_seconds_remaining = 86400

  revoke = false
}

################################################################################
# Test 75: Issue Short-lived Certificate
################################################################################
resource "vault_pki_secret_backend_cert" "short_lived_example" {
  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]

  backend     = vault_mount.pki_int.path
  name        = vault_pki_secret_backend_role.short_lived.name
  common_name = "ephemeral.example.com"

  ttl    = "3600"
  revoke = false  # Short-lived certs may expire before destroy; skip revocation
}

################################################################################
# Outputs
################################################################################

output "pki_mounts" {
  value = {
    root = vault_mount.pki_root.path
    int  = vault_mount.pki_int.path
  }
  description = "PKI secrets engine mount paths"
}

output "pki_ca_chain" {
  value = {
    root_ca      = vault_pki_secret_backend_root_cert.root.certificate
    intermediate = vault_pki_secret_backend_root_sign_intermediate.int.certificate
  }
  description = "CA certificates"
}

output "pki_roles" {
  value = {
    server       = vault_pki_secret_backend_role.server.name
    client       = vault_pki_secret_backend_role.client.name
    wildcard     = vault_pki_secret_backend_role.wildcard.name
    short_lived  = vault_pki_secret_backend_role.short_lived.name
    service_mesh = vault_pki_secret_backend_role.service_mesh.name
  }
  description = "PKI role names"
}

output "pki_certificates" {
  value = {
    server_cert = {
      serial_number = vault_pki_secret_backend_cert.server_example.serial_number
      expiration    = vault_pki_secret_backend_cert.server_example.expiration
    }
    client_cert = {
      serial_number = vault_pki_secret_backend_cert.client_example.serial_number
      expiration    = vault_pki_secret_backend_cert.client_example.expiration
    }
    wildcard_cert = {
      serial_number = vault_pki_secret_backend_cert.wildcard_example.serial_number
      expiration    = vault_pki_secret_backend_cert.wildcard_example.expiration
    }
  }
  description = "Issued certificate details"
}

output "pki_cert_values" {
  value = {
    server_certificate   = vault_pki_secret_backend_cert.server_example.certificate
    server_private_key   = vault_pki_secret_backend_cert.server_example.private_key
    server_ca_chain      = vault_pki_secret_backend_cert.server_example.ca_chain
  }
  sensitive   = true
  description = "Certificate values (sensitive)"
}
