# test-06-transit.tf
# Tests 76-90: Transit Secrets Engine
# Tests: encryption keys, encryption/decryption, key rotation, HMAC, signatures

################################################################################
# Transit Secrets Engine Mount
################################################################################
resource "vault_mount" "transit" {
  path        = "${local.name_prefix}-transit"
  type        = "transit"
  description = "Transit secrets engine for Warden testing"

  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

################################################################################
# Test 76: AES-256-GCM Key (default encryption)
################################################################################
resource "vault_transit_secret_backend_key" "aes_gcm" {
  backend = vault_mount.transit.path
  name    = "aes-gcm-key"
  type    = "aes256-gcm96"

  deletion_allowed         = true
  exportable               = false
  allow_plaintext_backup   = false
  min_decryption_version   = 1
  min_encryption_version   = 0
  convergent_encryption    = false
  derived                  = false
  auto_rotate_period       = 0
}

################################################################################
# Test 77: ChaCha20-Poly1305 Key
################################################################################
resource "vault_transit_secret_backend_key" "chacha20" {
  backend = vault_mount.transit.path
  name    = "chacha20-key"
  type    = "chacha20-poly1305"

  deletion_allowed = true
  exportable       = false
}

################################################################################
# Test 78: RSA-4096 Key (for signing/verification)
################################################################################
resource "vault_transit_secret_backend_key" "rsa_4096" {
  backend = vault_mount.transit.path
  name    = "rsa-4096-key"
  type    = "rsa-4096"

  deletion_allowed = true
  exportable       = false
}

################################################################################
# Test 79: RSA-2048 Key (for encryption)
################################################################################
resource "vault_transit_secret_backend_key" "rsa_2048" {
  backend = vault_mount.transit.path
  name    = "rsa-2048-key"
  type    = "rsa-2048"

  deletion_allowed = true
  exportable       = true # Allow export for testing
}

################################################################################
# Test 80: ECDSA P-256 Key (for signing)
################################################################################
resource "vault_transit_secret_backend_key" "ecdsa_p256" {
  backend = vault_mount.transit.path
  name    = "ecdsa-p256-key"
  type    = "ecdsa-p256"

  deletion_allowed = true
  exportable       = false
}

################################################################################
# Test 81: ECDSA P-384 Key
################################################################################
resource "vault_transit_secret_backend_key" "ecdsa_p384" {
  backend = vault_mount.transit.path
  name    = "ecdsa-p384-key"
  type    = "ecdsa-p384"

  deletion_allowed = true
  exportable       = false
}

################################################################################
# Test 82: ED25519 Key (for signing)
################################################################################
resource "vault_transit_secret_backend_key" "ed25519" {
  backend = vault_mount.transit.path
  name    = "ed25519-key"
  type    = "ed25519"

  deletion_allowed = true
  exportable       = false
}

################################################################################
# Test 83: Convergent Encryption Key
################################################################################
resource "vault_transit_secret_backend_key" "convergent" {
  backend = vault_mount.transit.path
  name    = "convergent-key"
  type    = "aes256-gcm96"

  deletion_allowed      = true
  convergent_encryption = true
  derived               = true
}

################################################################################
# Test 84: Key with Auto-Rotation
################################################################################
resource "vault_transit_secret_backend_key" "auto_rotate" {
  backend = vault_mount.transit.path
  name    = "auto-rotate-key"
  type    = "aes256-gcm96"

  deletion_allowed   = true
  auto_rotate_period = 86400 # Rotate daily
}

################################################################################
# Test 85: Key with Version Constraints
################################################################################
resource "vault_transit_secret_backend_key" "version_constrained" {
  backend = vault_mount.transit.path
  name    = "version-constrained-key"
  type    = "aes256-gcm96"

  deletion_allowed       = true
  min_decryption_version = 1
  min_encryption_version = 1
}

################################################################################
# Test 86: Exportable Key (for backup scenarios)
################################################################################
resource "vault_transit_secret_backend_key" "exportable" {
  backend = vault_mount.transit.path
  name    = "exportable-key"
  type    = "aes256-gcm96"

  deletion_allowed       = true
  exportable             = true
  allow_plaintext_backup = true
}

################################################################################
# Test 87: HMAC-only Key (SHA256)
################################################################################
resource "vault_transit_secret_backend_key" "hmac_sha256" {
  backend  = vault_mount.transit.path
  name     = "hmac-sha256-key"
  type     = "hmac"
  key_size = 32  # HMAC keys must be between 32 and 512 bytes

  deletion_allowed = true
}

################################################################################
# Test 88: Key for Database Encryption
################################################################################
resource "vault_transit_secret_backend_key" "database_encryption" {
  backend = vault_mount.transit.path
  name    = "database-field-encryption"
  type    = "aes256-gcm96"

  deletion_allowed = true

  # Keep multiple versions for key rotation
  min_decryption_version = 1
  min_encryption_version = 0 # Always use latest
}

################################################################################
# Test 89: Key for Application Secrets
################################################################################
resource "vault_transit_secret_backend_key" "app_secrets" {
  backend = vault_mount.transit.path
  name    = "app-secrets-key"
  type    = "aes256-gcm96"

  deletion_allowed   = true
  auto_rotate_period = 604800 # Weekly rotation
}

################################################################################
# Test 90: Key for API Token Encryption
################################################################################
resource "vault_transit_secret_backend_key" "api_tokens" {
  backend = vault_mount.transit.path
  name    = "api-tokens-key"
  type    = "aes256-gcm96"

  deletion_allowed = true

  # Convergent for searchable encrypted tokens
  convergent_encryption = true
  derived               = true
}

################################################################################
# Transit Cache Configuration
################################################################################
resource "vault_transit_secret_cache_config" "cache" {
  backend = vault_mount.transit.path
  size    = 500 # Cache size for key versions
}

################################################################################
# Outputs
################################################################################

output "transit_mount_path" {
  value       = vault_mount.transit.path
  description = "Transit secrets engine mount path"
}

output "transit_keys" {
  value = {
    aes_gcm = {
      name = vault_transit_secret_backend_key.aes_gcm.name
      type = vault_transit_secret_backend_key.aes_gcm.type
    }
    chacha20 = {
      name = vault_transit_secret_backend_key.chacha20.name
      type = vault_transit_secret_backend_key.chacha20.type
    }
    rsa_4096 = {
      name = vault_transit_secret_backend_key.rsa_4096.name
      type = vault_transit_secret_backend_key.rsa_4096.type
    }
    rsa_2048 = {
      name = vault_transit_secret_backend_key.rsa_2048.name
      type = vault_transit_secret_backend_key.rsa_2048.type
    }
    ecdsa_p256 = {
      name = vault_transit_secret_backend_key.ecdsa_p256.name
      type = vault_transit_secret_backend_key.ecdsa_p256.type
    }
    ecdsa_p384 = {
      name = vault_transit_secret_backend_key.ecdsa_p384.name
      type = vault_transit_secret_backend_key.ecdsa_p384.type
    }
    ed25519 = {
      name = vault_transit_secret_backend_key.ed25519.name
      type = vault_transit_secret_backend_key.ed25519.type
    }
    convergent = {
      name = vault_transit_secret_backend_key.convergent.name
      type = vault_transit_secret_backend_key.convergent.type
    }
    auto_rotate = {
      name = vault_transit_secret_backend_key.auto_rotate.name
      type = vault_transit_secret_backend_key.auto_rotate.type
    }
    hmac = {
      name = vault_transit_secret_backend_key.hmac_sha256.name
      type = vault_transit_secret_backend_key.hmac_sha256.type
    }
  }
  description = "Transit key details"
}

output "transit_key_names" {
  value = [
    vault_transit_secret_backend_key.aes_gcm.name,
    vault_transit_secret_backend_key.chacha20.name,
    vault_transit_secret_backend_key.rsa_4096.name,
    vault_transit_secret_backend_key.rsa_2048.name,
    vault_transit_secret_backend_key.ecdsa_p256.name,
    vault_transit_secret_backend_key.ecdsa_p384.name,
    vault_transit_secret_backend_key.ed25519.name,
    vault_transit_secret_backend_key.convergent.name,
    vault_transit_secret_backend_key.auto_rotate.name,
    vault_transit_secret_backend_key.version_constrained.name,
    vault_transit_secret_backend_key.exportable.name,
    vault_transit_secret_backend_key.hmac_sha256.name,
    vault_transit_secret_backend_key.database_encryption.name,
    vault_transit_secret_backend_key.app_secrets.name,
    vault_transit_secret_backend_key.api_tokens.name,
  ]
  description = "All transit key names"
}

output "transit_encryption_keys" {
  value = {
    aes_gcm  = vault_transit_secret_backend_key.aes_gcm.name
    chacha20 = vault_transit_secret_backend_key.chacha20.name
    rsa_2048 = vault_transit_secret_backend_key.rsa_2048.name
  }
  description = "Keys suitable for encryption"
}

output "transit_signing_keys" {
  value = {
    rsa_4096   = vault_transit_secret_backend_key.rsa_4096.name
    ecdsa_p256 = vault_transit_secret_backend_key.ecdsa_p256.name
    ecdsa_p384 = vault_transit_secret_backend_key.ecdsa_p384.name
    ed25519    = vault_transit_secret_backend_key.ed25519.name
  }
  description = "Keys suitable for signing"
}
