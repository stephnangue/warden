# test-03-iam.tf
# Tests 9-13: Scaleway IAM operations via restapi/http (zero cost)
# Validates: IAM application, policy, API key CRUD through the gateway

locals {
  api_key_expires_at = timeadd(timestamp(), "1h")
}

################################################################################
# Test 9: Create an IAM application
# Verifies IAM API access through the gateway
# Cost: FREE
################################################################################
resource "restapi_object" "test_09_application" {
  path         = "/iam/v1alpha1/applications"
  read_path    = "/iam/v1alpha1/applications/{id}"
  destroy_path = "/iam/v1alpha1/applications/{id}"

  data = jsonencode({
    name            = "${local.name_prefix}-app"
    description     = "Warden Scaleway e2e test application"
    organization_id = var.scaleway_organization_id
  })
}

################################################################################
# Test 10: Create an IAM policy for the application
# Verifies policy creation with nested rules
# Cost: FREE
################################################################################
resource "restapi_object" "test_10_policy" {
  path         = "/iam/v1alpha1/policies"
  read_path    = "/iam/v1alpha1/policies/{id}"
  destroy_path = "/iam/v1alpha1/policies/{id}"

  data = jsonencode({
    name            = "${local.name_prefix}-policy"
    description     = "Warden e2e test policy - read-only Object Storage"
    organization_id = var.scaleway_organization_id
    application_id  = restapi_object.test_09_application.id
    rules = [
      {
        project_ids          = [var.scaleway_project_id]
        permission_set_names = ["ObjectStorageReadOnly"]
      }
    ]
  })

  depends_on = [restapi_object.test_09_application]
}

################################################################################
# Test 11: Create an API key for the application
# Verifies POST /iam/v1alpha1/api-keys (same endpoint used by the driver)
# Cost: FREE
################################################################################
resource "restapi_object" "test_11_api_key" {
  path         = "/iam/v1alpha1/api-keys"
  read_path    = "/iam/v1alpha1/api-keys/{id}"
  destroy_path = "/iam/v1alpha1/api-keys/{id}"

  data = jsonencode({
    application_id     = restapi_object.test_09_application.id
    description        = "Warden e2e test key"
    default_project_id = var.scaleway_project_id
    expires_at         = local.api_key_expires_at
  })

  id_attribute = "access_key"

  depends_on = [restapi_object.test_09_application]
}

################################################################################
# Test 12: Read back the API key
# Verifies GET /iam/v1alpha1/api-keys/{access_key}
# Cost: FREE (read-only)
################################################################################
data "http" "test_12_api_key_read" {
  url             = "${var.warden_address}/iam/v1alpha1/api-keys/${restapi_object.test_11_api_key.id}"
  request_headers = local.common_headers

  depends_on = [restapi_object.test_11_api_key]
}

################################################################################
# Test 13: Create a second application
# Verifies multiple IAM resources can coexist
# Cost: FREE
################################################################################
resource "restapi_object" "test_13_application_2" {
  path         = "/iam/v1alpha1/applications"
  read_path    = "/iam/v1alpha1/applications/{id}"
  destroy_path = "/iam/v1alpha1/applications/{id}"

  data = jsonencode({
    name            = "${local.name_prefix}-app-2"
    description     = "Warden Scaleway e2e second test application"
    organization_id = var.scaleway_organization_id
  })
}

################################################################################
# Outputs
################################################################################

output "test_09_application" {
  value = {
    id = restapi_object.test_09_application.id
  }
  description = "Test 9: IAM application"
}

output "test_10_policy" {
  value = {
    id = restapi_object.test_10_policy.id
  }
  description = "Test 10: IAM policy"
}

output "test_11_api_key" {
  value = {
    access_key = restapi_object.test_11_api_key.id
  }
  description = "Test 11: IAM API key"
  sensitive   = true
}

output "test_12_api_key_read" {
  value = {
    status_code    = data.http.test_12_api_key_read.status_code
    application_id = try(jsondecode(data.http.test_12_api_key_read.response_body).application_id, "")
  }
  description = "Test 12: IAM API key read-back"
}

output "test_13_application_2" {
  value = {
    id = restapi_object.test_13_application_2.id
  }
  description = "Test 13: Second IAM application"
}
