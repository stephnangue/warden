# test-01-api.tf
# Tests 1-6: Cloudflare REST API operations via http data source (zero cost)
# Validates: Bearer token injection, GET proxying, various Cloudflare API endpoints

################################################################################
# Test 1: List zones
# Verifies the gateway injects the Bearer token and proxies GET /zones
# Cost: FREE (read-only)
################################################################################
data "http" "test_01_zones" {
  url             = "${var.warden_address}/zones"
  request_headers = local.common_headers
}

################################################################################
# Test 2: Verify API token
# Verifies GET /user/tokens/verify through the gateway
# Cost: FREE (read-only)
################################################################################
data "http" "test_02_verify_token" {
  url             = "${var.warden_address}/user/tokens/verify"
  request_headers = local.common_headers
}

################################################################################
# Test 3: Get user details
# Verifies GET /user through the gateway
# Cost: FREE (read-only)
################################################################################
data "http" "test_03_user" {
  url             = "${var.warden_address}/user"
  request_headers = local.common_headers
}

################################################################################
# Test 4: List accounts
# Verifies GET /accounts through the gateway
# Cost: FREE (read-only)
################################################################################
data "http" "test_04_accounts" {
  url             = "${var.warden_address}/accounts"
  request_headers = local.common_headers
}

################################################################################
# Test 5: List zones with query parameters
# Verifies query string passthrough (per_page, status filter)
# Cost: FREE (read-only)
################################################################################
data "http" "test_05_zones_filtered" {
  url             = "${var.warden_address}/zones?per_page=5&status=active"
  request_headers = local.common_headers
}

################################################################################
# Test 6: List zone DNS records (requires at least one zone)
# Verifies nested resource path /zones/{zone_id}/dns_records
# Cost: FREE (read-only)
# Note: Uses the first zone from test 1; skips if no zones exist
################################################################################
data "http" "test_06_dns_records" {
  count = try(length(jsondecode(data.http.test_01_zones.response_body).result), 0) > 0 ? 1 : 0

  url             = "${var.warden_address}/zones/${jsondecode(data.http.test_01_zones.response_body).result[0].id}/dns_records"
  request_headers = local.common_headers
}

################################################################################
# Outputs
################################################################################

output "test_01_zones" {
  value = {
    status_code = data.http.test_01_zones.status_code
    zone_count  = try(length(jsondecode(data.http.test_01_zones.response_body).result), 0)
  }
  description = "Test 1: List zones"
}

output "test_02_verify_token" {
  value = {
    status_code = data.http.test_02_verify_token.status_code
    success     = try(jsondecode(data.http.test_02_verify_token.response_body).success, false)
  }
  description = "Test 2: Verify API token"
}

output "test_03_user" {
  value = {
    status_code = data.http.test_03_user.status_code
    success     = try(jsondecode(data.http.test_03_user.response_body).success, false)
  }
  description = "Test 3: Get user details"
}

output "test_04_accounts" {
  value = {
    status_code   = data.http.test_04_accounts.status_code
    account_count = try(length(jsondecode(data.http.test_04_accounts.response_body).result), 0)
  }
  description = "Test 4: List accounts"
}

output "test_05_zones_filtered" {
  value = {
    status_code = data.http.test_05_zones_filtered.status_code
  }
  description = "Test 5: List zones with query params"
}

output "test_06_dns_records" {
  value = {
    status_code = try(data.http.test_06_dns_records[0].status_code, "skipped")
  }
  description = "Test 6: Zone DNS records (skipped if no zones)"
}
