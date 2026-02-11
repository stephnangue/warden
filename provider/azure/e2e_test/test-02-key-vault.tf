# test-02-key-vault.tf
# Tests 7-14: Azure Key Vault operations through Warden gateway
# Validates: ARM control-plane provisioning + data-plane secret/key operations
# Data-plane tests require var.keyvault_name to be set

locals {
  kv_api_version      = "2023-07-01"
  kv_data_api_version = "7.4"
  kv_rg_name          = "${local.name_prefix}-kv"
  kv_name             = "wkv${random_id.suffix.hex}"
  kv_base_path        = "${local.arm_base}/resourceGroups/${local.kv_rg_name}/providers/Microsoft.KeyVault/vaults"
}

################################################################################
# Test 7: Create resource group for Key Vault tests
################################################################################
resource "restapi_object" "rg_keyvault" {
  path         = "${local.rg_base_path}/${local.kv_rg_name}?api-version=${local.rg_api_version}"
  read_path    = "${local.rg_base_path}/${local.kv_rg_name}?api-version=${local.rg_api_version}"
  update_path  = "${local.rg_base_path}/${local.kv_rg_name}?api-version=${local.rg_api_version}"
  destroy_path = "${local.rg_base_path}/${local.kv_rg_name}?api-version=${local.rg_api_version}"

  data = jsonencode({
    name     = local.kv_rg_name
    location = var.location
    tags = merge(local.common_tags, {
      Name       = "Key Vault Resource Group"
      TestNumber = "07"
    })
  })
}

################################################################################
# Test 8: Create a Key Vault via ARM
################################################################################
resource "restapi_object" "keyvault" {
  path         = "${local.kv_base_path}/${local.kv_name}?api-version=${local.kv_api_version}"
  read_path    = "${local.kv_base_path}/${local.kv_name}?api-version=${local.kv_api_version}"
  update_path  = "${local.kv_base_path}/${local.kv_name}?api-version=${local.kv_api_version}"
  destroy_path = "${local.kv_base_path}/${local.kv_name}?api-version=${local.kv_api_version}"

  data = jsonencode({
    name     = local.kv_name
    location = var.location
    properties = {
      tenantId                 = var.tenant_id
      sku                      = { family = "A", name = "standard" }
      enableSoftDelete         = true
      softDeleteRetentionInDays = 7
      enableRbacAuthorization  = true

      networkAcls = {
        defaultAction = "Allow"
        bypass        = "AzureServices"
      }
    }
    tags = merge(local.common_tags, {
      Name       = "Test Key Vault"
      TestNumber = "08"
    })
  })

  depends_on = [restapi_object.rg_keyvault]
}

################################################################################
# Test 9: Read Key Vault properties via ARM
################################################################################
data "http" "keyvault_read" {
  url = "${var.warden_address}/management.azure.com${local.kv_base_path}/${local.kv_name}?api-version=${local.kv_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.keyvault]
}

################################################################################
# Test 10: List Key Vaults in resource group
################################################################################
data "http" "keyvault_list" {
  url = "${var.warden_address}/management.azure.com${local.kv_base_path}?api-version=${local.kv_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.keyvault]
}

################################################################################
# Test 11: Set a secret via Key Vault data plane (*.vault.azure.net)
# Only runs if var.keyvault_name is set (existing KV with access configured)
################################################################################
resource "terraform_data" "kv_set_secret" {
  count = var.keyvault_name != "" ? 1 : 0

  input = {
    secret_name  = "warden-test-secret"
    secret_value = "test-value-${random_id.suffix.hex}"
  }

  provisioner "local-exec" {
    command = <<-EOT
      curl -sf -X PUT \
        "${var.warden_address}/${var.keyvault_name}.vault.azure.net/secrets/${self.input.secret_name}?api-version=${local.kv_data_api_version}" \
        -H "Authorization: Bearer ${var.access_token}" \
        -H "Content-Type: application/json" \
        -d '{"value": "${self.input.secret_value}", "attributes": {"enabled": true}}'
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      echo "Secret will expire naturally or be cleaned up manually"
    EOT
  }
}

################################################################################
# Test 12: Get a secret via Key Vault data plane
################################################################################
data "http" "kv_get_secret" {
  count = var.keyvault_name != "" ? 1 : 0

  url = "${var.warden_address}/${var.keyvault_name}.vault.azure.net/secrets/warden-test-secret?api-version=${local.kv_data_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [terraform_data.kv_set_secret]
}

################################################################################
# Test 13: List secrets in Key Vault
################################################################################
data "http" "kv_list_secrets" {
  count = var.keyvault_name != "" ? 1 : 0

  url = "${var.warden_address}/${var.keyvault_name}.vault.azure.net/secrets?api-version=${local.kv_data_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [terraform_data.kv_set_secret]
}

################################################################################
# Test 14: Create a key in Key Vault
################################################################################
resource "terraform_data" "kv_create_key" {
  count = var.keyvault_name != "" ? 1 : 0

  input = {
    key_name = "warden-test-key"
  }

  provisioner "local-exec" {
    command = <<-EOT
      curl -sf -X POST \
        "${var.warden_address}/${var.keyvault_name}.vault.azure.net/keys/${self.input.key_name}/create?api-version=${local.kv_data_api_version}" \
        -H "Authorization: Bearer ${var.access_token}" \
        -H "Content-Type: application/json" \
        -d '{"kty": "RSA", "key_size": 2048, "key_ops": ["encrypt", "decrypt", "sign", "verify"]}'
    EOT
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      echo "Key will be cleaned up manually"
    EOT
  }
}

################################################################################
# Outputs
################################################################################

output "keyvault_name" {
  value       = local.kv_name
  description = "Key Vault name created via ARM"
}

output "keyvault_read_status" {
  value       = data.http.keyvault_read.status_code
  description = "Read Key Vault HTTP status"
}

output "kv_secret_status" {
  value       = var.keyvault_name != "" ? data.http.kv_get_secret[0].status_code : null
  description = "Get secret HTTP status (null if data-plane tests skipped)"
}
