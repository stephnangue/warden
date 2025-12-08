#!/usr/bin/env bash

# Integration test script
# Tests complete workflows end-to-end

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

test_provider_full_workflow() {
    log_info "Test: Complete provider workflow"

    # Enable provider
    local output
    output=$(run_warden providers enable --type=aws --description="Test Provider")
    assert_success $? "Failed to enable provider"
    assert_contains "$output" "aws" "Provider path not in enable output"

    # Configure provider
    output=$(run_warden write sys/providers/aws/config <<EOF
{
  "proxy_domains": ["localhost", "warden"],
  "max_body_size": 10485760,
  "timeout": "60s"
}
EOF
)
    assert_success $? "Failed to configure provider"

    # Read provider
    output=$(run_warden providers read --path=aws)
    assert_success $? "Failed to read provider"
    assert_contains "$output" "aws" "Path not in read output"

    # List providers
    output=$(run_warden providers list)
    assert_success $? "Failed to list providers"
    assert_contains "$output" "aws/" "Provider not listed"

    # Disable provider
    output=$(run_warden providers disable --path=aws)
    assert_success $? "Failed to disable provider"

    # Verify removed
    output=$(run_warden providers list)
    assert_not_contains "$output" "aws/" "Provider still listed after disable"

    log_success "✓ Complete provider workflow passed"
}

test_auth_full_workflow() {
    log_info "Test: Complete auth workflow"

    # Enable auth
    local output
    output=$(run_warden auth enable --type=jwt --description="Test Auth")
    assert_success $? "Failed to enable auth"
    assert_contains "$output" "jwt" "Auth path not in enable output"

    # Configure auth
    output=$(run_warden write sys/auth/jwt/config <<EOF
{
  "mode": "jwt",
  "jwks_url": "https://example.com/.well-known/jwks.json",
  "bound_issuer": "https://example.com",
  "token_ttl": "1h",
  "auth_deadline": "10m"
}
EOF
)
    assert_success $? "Failed to configure auth"

    # Read auth
    output=$(run_warden auth read --path=jwt)
    assert_success $? "Failed to read auth"
    assert_contains "$output" "jwt" "Path not in read output"

    # List auth methods
    output=$(run_warden auth list)
    assert_success $? "Failed to list auth methods"
    assert_contains "$output" "jwt/" "Auth not listed"

    # Disable auth
    output=$(run_warden auth disable --path=jwt)
    assert_success $? "Failed to disable auth"

    # Verify removed
    output=$(run_warden auth list)
    assert_not_contains "$output" "jwt/" "Auth still listed after disable"

    log_success "✓ Complete auth workflow passed"
}

test_concurrent_providers_and_auth() {
    log_info "Test: Multiple providers and auth methods concurrently"

    # Enable multiple providers
    run_warden providers enable --type=aws --path=aws-prod >/dev/null
    run_warden providers enable --type=aws --path=aws-staging >/dev/null

    # Enable multiple auth methods
    run_warden auth enable --type=jwt --path=jwt-prod >/dev/null
    run_warden auth enable --type=jwt --path=jwt-staging >/dev/null

    # List and verify all are present
    local providers
    providers=$(run_warden providers list)
    assert_contains "$providers" "aws-prod/" "aws-prod not listed"
    assert_contains "$providers" "aws-staging/" "aws-staging not listed"

    local auth_methods
    auth_methods=$(run_warden auth list)
    assert_contains "$auth_methods" "jwt-prod/" "jwt-prod not listed"
    assert_contains "$auth_methods" "jwt-staging/" "jwt-staging not listed"

    # Clean up
    run_warden providers disable --path=aws-prod >/dev/null
    run_warden providers disable --path=aws-staging >/dev/null
    run_warden auth disable --path=jwt-prod >/dev/null
    run_warden auth disable --path=jwt-staging >/dev/null

    log_success "✓ Concurrent providers and auth methods work"
}

# Main execution
main() {
    log_info "========================================"
    log_info "Running Integration Tests"
    log_info "========================================"

    test_provider_full_workflow
    test_auth_full_workflow
    test_concurrent_providers_and_auth

    log_success "All integration tests completed!"
}

main "$@"
