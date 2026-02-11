# test-01-resource-groups.tf
# Tests 1-6: Azure Resource Group CRUD operations through Warden gateway
# Validates: ARM API proxying, PUT/GET/PATCH/DELETE, tag management

locals {
  rg_api_version = "2024-03-01"
  rg_base_path   = "${local.arm_base}/resourcegroups"
}

################################################################################
# Test 1: Create a basic resource group
################################################################################
resource "restapi_object" "rg_basic" {
  path         = "${local.rg_base_path}/${local.name_prefix}-basic?api-version=${local.rg_api_version}"
  read_path    = "${local.rg_base_path}/${local.name_prefix}-basic?api-version=${local.rg_api_version}"
  update_path  = "${local.rg_base_path}/${local.name_prefix}-basic?api-version=${local.rg_api_version}"
  destroy_path = "${local.rg_base_path}/${local.name_prefix}-basic?api-version=${local.rg_api_version}"

  data = jsonencode({
    name     = "${local.name_prefix}-basic"
    location = var.location
    tags = merge(local.common_tags, {
      Name       = "Basic Resource Group"
      TestNumber = "01"
    })
  })
}

################################################################################
# Test 2: Create a resource group in a different region
################################################################################
resource "restapi_object" "rg_westus" {
  path         = "${local.rg_base_path}/${local.name_prefix}-westus?api-version=${local.rg_api_version}"
  read_path    = "${local.rg_base_path}/${local.name_prefix}-westus?api-version=${local.rg_api_version}"
  update_path  = "${local.rg_base_path}/${local.name_prefix}-westus?api-version=${local.rg_api_version}"
  destroy_path = "${local.rg_base_path}/${local.name_prefix}-westus?api-version=${local.rg_api_version}"

  data = jsonencode({
    name     = "${local.name_prefix}-westus"
    location = "westus2"
    tags = merge(local.common_tags, {
      Name       = "West US Resource Group"
      TestNumber = "02"
    })
  })
}

################################################################################
# Test 3: Create a resource group with extended tags
################################################################################
resource "restapi_object" "rg_tagged" {
  path         = "${local.rg_base_path}/${local.name_prefix}-tagged?api-version=${local.rg_api_version}"
  read_path    = "${local.rg_base_path}/${local.name_prefix}-tagged?api-version=${local.rg_api_version}"
  update_path  = "${local.rg_base_path}/${local.name_prefix}-tagged?api-version=${local.rg_api_version}"
  destroy_path = "${local.rg_base_path}/${local.name_prefix}-tagged?api-version=${local.rg_api_version}"

  data = jsonencode({
    name     = "${local.name_prefix}-tagged"
    location = var.location
    tags = merge(local.common_tags, {
      Name          = "Tagged Resource Group"
      TestNumber    = "03"
      CostCenter    = "warden-testing"
      Owner         = "platform-team"
      Compliance    = "internal"
      AutoShutdown  = "true"
      RetentionDays = "7"
    })
  })
}

################################################################################
# Test 4: Read a resource group (data source via http)
################################################################################
data "http" "rg_read" {
  url = "${var.warden_address}/management.azure.com${local.rg_base_path}/${local.name_prefix}-basic?api-version=${local.rg_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.rg_basic]
}

################################################################################
# Test 5: List all resource groups in subscription
################################################################################
data "http" "rg_list" {
  url = "${var.warden_address}/management.azure.com${local.rg_base_path}?api-version=${local.rg_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.rg_basic]
}

################################################################################
# Test 6: List resources within a resource group
################################################################################
data "http" "rg_resources" {
  url = "${var.warden_address}/management.azure.com${local.rg_base_path}/${local.name_prefix}-basic/resources?api-version=${local.rg_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.rg_basic]
}

################################################################################
# Outputs
################################################################################

output "rg_basic_response" {
  value       = jsondecode(restapi_object.rg_basic.api_response)
  description = "Basic resource group creation response"
}

output "rg_read_status" {
  value       = data.http.rg_read.status_code
  description = "Read resource group HTTP status"
}

output "rg_list_status" {
  value       = data.http.rg_list.status_code
  description = "List resource groups HTTP status"
}

output "rg_names" {
  value = {
    basic  = "${local.name_prefix}-basic"
    westus = "${local.name_prefix}-westus"
    tagged = "${local.name_prefix}-tagged"
  }
  description = "Resource group names created by tests"
}
