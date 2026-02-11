# test-04-networking.tf
# Tests 21-28: Azure Networking operations through Warden gateway
# Validates: VNet, Subnet, NSG, and NSG rule CRUD via ARM proxy
#
# NOTE: Azure networking DELETE operations are async (return 202). The restapi
# provider doesn't poll for completion, so time_sleep resources with
# destroy_duration are inserted to prevent 409 "AnotherOperationInProgress"
# errors during terraform destroy.

locals {
  net_api_version = "2024-01-01"
  net_rg_name     = "${local.name_prefix}-net"
  vnet_base_path  = "${local.arm_base}/resourceGroups/${local.net_rg_name}/providers/Microsoft.Network"
}

################################################################################
# Test 21: Create resource group for networking tests
################################################################################
resource "restapi_object" "rg_networking" {
  path         = "${local.rg_base_path}/${local.net_rg_name}?api-version=${local.rg_api_version}"
  read_path    = "${local.rg_base_path}/${local.net_rg_name}?api-version=${local.rg_api_version}"
  update_path  = "${local.rg_base_path}/${local.net_rg_name}?api-version=${local.rg_api_version}"
  destroy_path = "${local.rg_base_path}/${local.net_rg_name}?api-version=${local.rg_api_version}"

  data = jsonencode({
    name     = local.net_rg_name
    location = var.location
    tags = merge(local.common_tags, {
      Name       = "Networking Resource Group"
      TestNumber = "21"
    })
  })
}

# Destroy: wait after VNet is deleted before deleting resource group
resource "time_sleep" "wait_net_vnet" {
  destroy_duration = "15s"
  depends_on       = [restapi_object.rg_networking]
}

################################################################################
# Test 22: Create a Virtual Network
################################################################################
resource "restapi_object" "vnet" {
  path         = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet?api-version=${local.net_api_version}"
  read_path    = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet?api-version=${local.net_api_version}"
  update_path  = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet?api-version=${local.net_api_version}"
  destroy_path = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet?api-version=${local.net_api_version}"

  data = jsonencode({
    name     = "${local.name_prefix}-vnet"
    location = var.location
    properties = {
      addressSpace = {
        addressPrefixes = ["10.0.0.0/16"]
      }
      dhcpOptions = {
        dnsServers = []
      }
    }
    tags = merge(local.common_tags, {
      Name       = "Test Virtual Network"
      TestNumber = "22"
    })
  })

  depends_on = [time_sleep.wait_net_vnet]
}

# Destroy: wait after subnets are deleted before deleting VNet
resource "time_sleep" "wait_net_subnets" {
  destroy_duration = "15s"
  depends_on       = [restapi_object.vnet]
}

################################################################################
# Test 23: Create a Subnet within the VNet
################################################################################
resource "restapi_object" "subnet_app" {
  path         = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet/subnets/app-subnet?api-version=${local.net_api_version}"
  read_path    = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet/subnets/app-subnet?api-version=${local.net_api_version}"
  update_path  = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet/subnets/app-subnet?api-version=${local.net_api_version}"
  destroy_path = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet/subnets/app-subnet?api-version=${local.net_api_version}"

  data = jsonencode({
    name = "app-subnet"
    properties = {
      addressPrefix = "10.0.1.0/24"
      serviceEndpoints = [
        { service = "Microsoft.Storage" },
        { service = "Microsoft.KeyVault" }
      ]
    }
  })

  depends_on = [time_sleep.wait_net_subnets]
}

################################################################################
# Test 24: Create a second Subnet (database tier)
################################################################################
resource "restapi_object" "subnet_db" {
  path         = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet/subnets/db-subnet?api-version=${local.net_api_version}"
  read_path    = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet/subnets/db-subnet?api-version=${local.net_api_version}"
  update_path  = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet/subnets/db-subnet?api-version=${local.net_api_version}"
  destroy_path = "${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet/subnets/db-subnet?api-version=${local.net_api_version}"

  data = jsonencode({
    name = "db-subnet"
    properties = {
      addressPrefix = "10.0.2.0/24"
    }
  })

  depends_on = [restapi_object.subnet_app]
}

################################################################################
# Test 25: Create a Network Security Group
################################################################################
resource "restapi_object" "nsg" {
  path         = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg?api-version=${local.net_api_version}"
  read_path    = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg?api-version=${local.net_api_version}"
  update_path  = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg?api-version=${local.net_api_version}"
  destroy_path = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg?api-version=${local.net_api_version}"

  data = jsonencode({
    name     = "${local.name_prefix}-nsg"
    location = var.location
    properties = {
      securityRules = []
    }
    tags = merge(local.common_tags, {
      Name       = "Test NSG"
      TestNumber = "25"
    })
  })

  depends_on = [restapi_object.rg_networking, restapi_object.subnet_db]
}

# Destroy: wait after NSG rules are deleted before deleting NSG
resource "time_sleep" "wait_net_nsg_rules" {
  destroy_duration = "15s"
  depends_on       = [restapi_object.nsg]
}

################################################################################
# Test 26: Add inbound HTTPS rule to NSG
################################################################################
resource "restapi_object" "nsg_rule_https" {
  path         = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg/securityRules/allow-https-inbound?api-version=${local.net_api_version}"
  read_path    = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg/securityRules/allow-https-inbound?api-version=${local.net_api_version}"
  update_path  = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg/securityRules/allow-https-inbound?api-version=${local.net_api_version}"
  destroy_path = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg/securityRules/allow-https-inbound?api-version=${local.net_api_version}"

  data = jsonencode({
    name = "allow-https-inbound"
    properties = {
      protocol                 = "Tcp"
      sourcePortRange          = "*"
      destinationPortRange     = "443"
      sourceAddressPrefix      = "*"
      destinationAddressPrefix = "*"
      access                   = "Allow"
      priority                 = 100
      direction                = "Inbound"
      description              = "Allow HTTPS inbound traffic"
    }
  })

  depends_on = [time_sleep.wait_net_nsg_rules]
}

################################################################################
# Test 27: Add outbound deny rule to NSG (depends on rule 26 to avoid 429)
################################################################################
resource "restapi_object" "nsg_rule_deny_outbound" {
  path         = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg/securityRules/deny-all-outbound?api-version=${local.net_api_version}"
  read_path    = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg/securityRules/deny-all-outbound?api-version=${local.net_api_version}"
  update_path  = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg/securityRules/deny-all-outbound?api-version=${local.net_api_version}"
  destroy_path = "${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg/securityRules/deny-all-outbound?api-version=${local.net_api_version}"

  data = jsonencode({
    name = "deny-all-outbound"
    properties = {
      protocol                 = "*"
      sourcePortRange          = "*"
      destinationPortRange     = "*"
      sourceAddressPrefix      = "*"
      destinationAddressPrefix = "Internet"
      access                   = "Deny"
      priority                 = 4000
      direction                = "Outbound"
      description              = "Deny all outbound internet traffic"
    }
  })

  depends_on = [restapi_object.nsg_rule_https]
}

################################################################################
# Test 28: Read VNet and list subnets
################################################################################
data "http" "vnet_read" {
  url = "${var.warden_address}/management.azure.com${local.vnet_base_path}/virtualNetworks/${local.name_prefix}-vnet?api-version=${local.net_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.subnet_db]
}

data "http" "nsg_read" {
  url = "${var.warden_address}/management.azure.com${local.vnet_base_path}/networkSecurityGroups/${local.name_prefix}-nsg?api-version=${local.net_api_version}"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }

  depends_on = [restapi_object.nsg_rule_deny_outbound]
}

################################################################################
# Outputs
################################################################################

output "vnet_response" {
  value       = data.http.vnet_read.status_code
  description = "Read VNet HTTP status"
}

output "nsg_response" {
  value       = data.http.nsg_read.status_code
  description = "Read NSG HTTP status"
}

output "networking_resources" {
  value = {
    vnet       = "${local.name_prefix}-vnet"
    subnet_app = "app-subnet"
    subnet_db  = "db-subnet"
    nsg        = "${local.name_prefix}-nsg"
  }
  description = "Networking resource names"
}
