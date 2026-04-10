# test-01-instances.tf
# Tests 1-3: Scaleway Instance operations via restapi/http (zero cost)
# Validates: X-Auth-Token injection, GET proxying, security group CRUD

################################################################################
# Test 1: List available instance images
# Verifies the gateway injects X-Auth-Token and proxies GET requests
# Cost: FREE (read-only)
################################################################################
data "http" "test_01_images" {
  url             = "${var.warden_address}/instance/v1/zones/${var.scaleway_zone}/images?per_page=1&arch=x86_64"
  request_headers = local.common_headers
}

################################################################################
# Test 2: Create a security group
# Verifies POST/DELETE operations through the gateway
# Cost: FREE (security groups are not billed)
################################################################################
resource "restapi_object" "test_02_security_group" {
  path         = "/instance/v1/zones/${var.scaleway_zone}/security_groups"
  read_path    = "/instance/v1/zones/${var.scaleway_zone}/security_groups/{id}"
  destroy_path = "/instance/v1/zones/${var.scaleway_zone}/security_groups/{id}"

  data = jsonencode({
    name                    = "${local.name_prefix}-sg"
    description             = "Warden Scaleway e2e test security group"
    project                 = var.scaleway_project_id
    inbound_default_policy  = "drop"
    outbound_default_policy = "accept"
    stateful                = true
  })

  id_attribute = "security_group/id"
}

################################################################################
# Test 3: Read back the security group
# Verifies GET with resource ID lookup
# Cost: FREE (read-only)
################################################################################
data "http" "test_03_sg_read" {
  url             = "${var.warden_address}/instance/v1/zones/${var.scaleway_zone}/security_groups/${restapi_object.test_02_security_group.id}"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_02_security_group]
}

################################################################################
# Outputs
################################################################################

output "test_01_images" {
  value = {
    status_code = data.http.test_01_images.status_code
    has_images  = try(length(jsondecode(data.http.test_01_images.response_body).images) > 0, false)
  }
  description = "Test 1: Instance images list"
}

output "test_02_security_group" {
  value = {
    id = restapi_object.test_02_security_group.id
  }
  description = "Test 2: Security group created"
}

output "test_03_sg_read" {
  value = {
    status_code = data.http.test_03_sg_read.status_code
    name        = try(jsondecode(data.http.test_03_sg_read.response_body).security_group.name, "")
  }
  description = "Test 3: Security group read-back"
}
