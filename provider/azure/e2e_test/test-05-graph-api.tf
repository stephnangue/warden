# test-05-graph-api.tf
# Tests 29-33: Microsoft Graph API operations through Warden gateway
# Validates: proxying to graph.microsoft.com (separate host from ARM)
# These are read-only tests against the MS Graph API

################################################################################
# Test 29: Get current service principal info via Graph
################################################################################
data "http" "graph_me" {
  url = "${var.warden_address}/graph.microsoft.com/v1.0/me"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }
}

################################################################################
# Test 30: List applications in tenant
################################################################################
data "http" "graph_applications" {
  url = "${var.warden_address}/graph.microsoft.com/v1.0/applications?$top=5"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }
}

################################################################################
# Test 31: List service principals in tenant
################################################################################
data "http" "graph_service_principals" {
  url = "${var.warden_address}/graph.microsoft.com/v1.0/servicePrincipals?$top=5"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }
}

################################################################################
# Test 32: Get organization details
################################################################################
data "http" "graph_organization" {
  url = "${var.warden_address}/graph.microsoft.com/v1.0/organization"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }
}

################################################################################
# Test 33: List domains in tenant
################################################################################
data "http" "graph_domains" {
  url = "${var.warden_address}/graph.microsoft.com/v1.0/domains"

  request_headers = {
    Authorization = "Bearer ${var.access_token}"
    Accept         = "application/json"
  }
}

################################################################################
# Outputs
################################################################################

output "graph_me_status" {
  value       = data.http.graph_me.status_code
  description = "Graph /me endpoint status"
}

output "graph_applications_status" {
  value       = data.http.graph_applications.status_code
  description = "Graph /applications endpoint status"
}

output "graph_service_principals_status" {
  value       = data.http.graph_service_principals.status_code
  description = "Graph /servicePrincipals endpoint status"
}

output "graph_organization_status" {
  value       = data.http.graph_organization.status_code
  description = "Graph /organization endpoint status"
}

output "graph_domains_status" {
  value       = data.http.graph_domains.status_code
  description = "Graph /domains endpoint status"
}
