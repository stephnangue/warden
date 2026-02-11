# test-03-storage.tf
# Tests 15-20: Azure Storage Account operations through Warden gateway
# Validates: ARM storage provisioning, blob data-plane reads

locals {
  storage_api_version = "2023-05-01"
  storage_rg_name     = "${local.name_prefix}-storage"
  # Storage account names: lowercase alphanumeric, 3-24 chars
  storage_name        = "wst${random_id.suffix.hex}"
  storage_base_path   = "${local.arm_base}/resourceGroups/${local.storage_rg_name}/providers/Microsoft.Storage/storageAccounts"
}

################################################################################
# Test 15: Create resource group for storage tests
################################################################################
resource "restapi_object" "rg_storage" {
  path         = "${local.rg_base_path}/${local.storage_rg_name}?api-version=${local.rg_api_version}"
  read_path    = "${local.rg_base_path}/${local.storage_rg_name}?api-version=${local.rg_api_version}"
  update_path  = "${local.rg_base_path}/${local.storage_rg_name}?api-version=${local.rg_api_version}"
  destroy_path = "${local.rg_base_path}/${local.storage_rg_name}?api-version=${local.rg_api_version}"

  data = jsonencode({
    name     = local.storage_rg_name
    location = var.location
    tags = merge(local.common_tags, {
      Name       = "Storage Resource Group"
      TestNumber = "15"
    })
  })
}

################################################################################
# Test 16: Create a standard storage account
################################################################################
resource "restapi_object" "storage_standard" {
  path         = "${local.storage_base_path}/${local.storage_name}?api-version=${local.storage_api_version}"
  read_path    = "${local.storage_base_path}/${local.storage_name}?api-version=${local.storage_api_version}"
  update_path  = "${local.storage_base_path}/${local.storage_name}?api-version=${local.storage_api_version}"
  destroy_path = "${local.storage_base_path}/${local.storage_name}?api-version=${local.storage_api_version}"

  data = jsonencode({
    name     = local.storage_name
    location = var.location
    sku = {
      name = "Standard_LRS"
    }
    kind = "StorageV2"
    properties = {
      supportsHttpsTrafficOnly = true
      minimumTlsVersion        = "TLS1_2"
      allowBlobPublicAccess    = false
      accessTier               = "Hot"
      networkAcls = {
        defaultAction = "Allow"
        bypass        = "AzureServices"
      }
    }
    tags = merge(local.common_tags, {
      Name       = "Standard Storage Account"
      TestNumber = "16"
    })
  })

  depends_on = [restapi_object.rg_storage]
}

################################################################################
# Test 17: Read storage account properties
################################################################################
data "http" "storage_read" {
  url = "${var.warden_address}/management.azure.com${local.storage_base_path}/${local.storage_name}?api-version=${local.storage_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.storage_standard]
}

################################################################################
# Test 18: List storage accounts in resource group
################################################################################
data "http" "storage_list" {
  url = "${var.warden_address}/management.azure.com${local.storage_base_path}?api-version=${local.storage_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.storage_standard]
}

################################################################################
# Wait for storage account async provisioning to complete
# ARM returns 202 for storage account creation; the account isn't usable until
# provisioningState reaches "Succeeded"
################################################################################
resource "time_sleep" "wait_for_storage" {
  create_duration = "30s"
  depends_on      = [restapi_object.storage_standard]
}

################################################################################
# Test 19: Create a blob container via ARM
################################################################################
resource "restapi_object" "blob_container" {
  path         = "${local.storage_base_path}/${local.storage_name}/blobServices/default/containers/warden-test-container?api-version=${local.storage_api_version}"
  read_path    = "${local.storage_base_path}/${local.storage_name}/blobServices/default/containers/warden-test-container?api-version=${local.storage_api_version}"
  update_path  = "${local.storage_base_path}/${local.storage_name}/blobServices/default/containers/warden-test-container?api-version=${local.storage_api_version}"
  destroy_path = "${local.storage_base_path}/${local.storage_name}/blobServices/default/containers/warden-test-container?api-version=${local.storage_api_version}"

  data = jsonencode({
    name = "warden-test-container"
    properties = {
      publicAccess = "None"
      metadata = {
        purpose = "warden-e2e-testing"
      }
    }
  })

  depends_on = [time_sleep.wait_for_storage]
}

################################################################################
# Test 20: List blob containers
################################################################################
data "http" "blob_containers_list" {
  url = "${var.warden_address}/management.azure.com${local.storage_base_path}/${local.storage_name}/blobServices/default/containers?api-version=${local.storage_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.blob_container]
}

################################################################################
# Outputs
################################################################################

output "storage_account_name" {
  value       = local.storage_name
  description = "Storage account name"
}

output "storage_read_status" {
  value       = data.http.storage_read.status_code
  description = "Read storage account HTTP status"
}

output "blob_container_response" {
  value       = jsondecode(restapi_object.blob_container.api_response)
  description = "Blob container creation response"
}
