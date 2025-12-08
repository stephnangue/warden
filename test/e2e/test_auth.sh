#!/usr/bin/env bash

# Test script for auth method lifecycle management
# Tests enable, list, read, and disable operations for auth methods

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

test_enable_auth_default_path() {
    log_info "Test: Enable JWT auth with default path"

    local output
    output=$(run_warden auth enable --type=jwt)
    local exit_code=$?

    assert_contains "$output" "jwt" "Output should contain mount path"

    log_success "✓ Auth method enabled with default path"
}

test_list_auth_methods() {
    log_info "Test: List auth methods"

    local output
    output=$(run_warden auth list)
    local exit_code=$?

    assert_contains "$output" "jwt/" "Auth method not in list"
    assert_contains "$output" "jwt" "Auth type not in list"

    log_success "✓ Auth methods listed successfully"
}

test_read_auth_method() {
    log_info "Test: Read auth method details"

    local output
    output=$(run_warden auth read --path=jwt)
    local exit_code=$?

    assert_contains "$output" "jwt" "Path not in output"
    assert_contains "$output" "jwt" "Type not in output"

    log_success "✓ Auth method read successfully"
}

test_enable_auth_custom_path() {
    log_info "Test: Enable auth with custom path and description"

    local output
    output=$(run_warden auth enable --type=jwt --path=jwt-prod --description="Production JWT")
    local exit_code=$?

    assert_success $exit_code "Failed to enable auth with custom path"

    # Verify it's listed
    output=$(run_warden auth list)
    assert_contains "$output" "jwt-prod/" "Custom path not in list"

    # Verify details
    output=$(run_warden auth read --path=jwt-prod)
    assert_contains "$output" "jwt-prod" "Path mismatch"
    assert_contains "$output" "Production JWT" "Description not found"

    log_success "✓ Auth enabled with custom path and description"
}

test_disable_auth() {
    log_info "Test: Disable auth method"

    # Disable the default jwt auth
    local output
    output=$(run_warden auth disable --path=jwt)
    local exit_code=$?

    # Verify it's no longer listed
    output=$(run_warden auth list)
    assert_not_contains "$output" "jwt/" "Auth method still in list after disable"

    log_success "✓ Auth method disabled successfully"
}

test_disable_nonexistent_auth_fails() {
    log_info "Test: Disabling non-existent auth should fail"

    local output
    output=$(run_warden auth disable --path=nonexistent 2>&1) || true
    local exit_code=$?

    assert_contains "$output" "no matching mount" "Error message should indicate mount not found"

    log_success "✓ Disabling non-existent auth correctly fails"
}

test_enable_multiple_auth_methods() {
    log_info "Test: Enable multiple auth methods"

    # Enable JWT at default path
    run_warden auth enable --type=jwt >/dev/null

    # Enable JWT at custom path
    run_warden auth enable --type=jwt --path=jwt-staging >/dev/null

    # List and verify both are present
    local output
    output=$(run_warden auth list)

    assert_contains "$output" "jwt/" "First auth method not listed"
    assert_contains "$output" "jwt-staging/" "Second auth method not listed"

    log_success "✓ Multiple auth methods enabled successfully"
}

# Main execution
main() {
    log_info "========================================"
    log_info "Running Auth Method Lifecycle Tests"
    log_info "========================================"

    test_enable_auth_default_path
    test_list_auth_methods
    test_read_auth_method
    test_enable_auth_custom_path
    test_disable_auth
    test_disable_nonexistent_auth_fails
    test_enable_multiple_auth_methods

    log_success "All auth method lifecycle tests completed!"

    run_warden auth disable --path=jwt >/dev/null
    run_warden auth disable --path=jwt-prod >/dev/null
    run_warden auth disable --path=jwt-staging >/dev/null
}

main "$@"
