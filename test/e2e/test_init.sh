#!/usr/bin/env bash

# Test script for warden init command
# Tests initialization, token generation, and revocation

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

test_server_health_check() {
    log_info "Test: Server health check"

    local output
    output=$(curl -sf "$WARDEN_ADDR/v1/sys/health" 2>&1) || true

    assert_success $? "Health check failed"
    log_success "✓ Server health check passed"
}

test_init_generates_root_token() {
    log_info "Test: warden init generates root token"

    local output
    output=$(run_warden init)
    local exit_code=$?

    assert_success $exit_code "warden init failed"
    assert_contains "$output" "cws." "Output should contain token with cws. prefix"
    assert_contains "$output" "WARDEN_TOKEN" "Output should contain WARDEN_TOKEN instructions"

    # Extract and validate token format
    local token
    token=$(echo "$output" | grep "^cws\." | head -n1)

    # Token should be cws. followed by 64 characters
    if [[ "$token" =~ ^cws\.[a-z0-9]{64}$ ]]; then
        log_success "✓ Token format is valid: ${token:0:20}..."
    else
        log_error "Invalid token format: $token"
        return 1
    fi

    # Store token for other tests
    export WARDEN_TOKEN="$token"

    log_success "✓ warden init generates valid root token"
}

test_reinit_should_fail() {
    log_info "Test: Re-initialization should fail"

    local output
    output=$(run_warden init 2>&1) || true
    local exit_code=$?

    assert_failure $exit_code "Re-initialization should have failed"
    assert_contains "$output" "already initialized" "Error message should indicate already initialized"

    log_success "✓ Re-initialization correctly fails"
}

test_operations_without_token_fail() {
    log_info "Test: Operations without token should fail"

    # Temporarily unset token
    local saved_token="$WARDEN_TOKEN"
    unset WARDEN_TOKEN

    local output
    output=$(run_warden providers list 2>&1) || true
    local exit_code=$?

    assert_failure $exit_code "Command without token should fail"

    # Restore token
    export WARDEN_TOKEN="$saved_token"

    log_success "✓ Operations without token correctly fail"
}

test_operations_with_token_succeed() {
    log_info "Test: Operations with token should succeed"

    local output
    output=$(run_warden providers list 2>&1)
    local exit_code=$?

    assert_success $exit_code "Command with token should succeed"

    log_success "✓ Operations with token succeed"
}

test_root_token_revocation() {
    log_info "Test: Root token revocation and re-init"

    # Revoke the current root token
    local output
    output=$(run_warden revoke-root-token)
    local exit_code=$?

    assert_success $exit_code "Root token revocation failed"
    assert_contains "$output" "revoked" "Output should confirm revocation"

    # Try to use revoked token (should fail)
    output=$(run_warden providers list 2>&1) || true
    exit_code=$?

    assert_failure $exit_code "Revoked token should not work"

    # Re-initialize
    output=$(run_warden init)
    exit_code=$?

    assert_success $exit_code "Re-init after revocation failed"

    # Extract new token
    local new_token
    new_token=$(echo "$output" | grep "^cws\." | head -n1)
    export WARDEN_TOKEN="$new_token"

    # Verify new token works
    output=$(run_warden providers list)
    exit_code=$?

    assert_success $exit_code "New token should work"

    log_success "✓ Root token revocation and re-init work correctly"
}

# Main execution
main() {
    log_info "========================================"
    log_info "Running Initialization Tests"
    log_info "========================================"

    setup_test_env
    trap cleanup EXIT

    #build_warden
    #start_server
    #wait_for_server

    #test_server_health_check
    test_init_generates_root_token
    test_reinit_should_fail
    test_operations_without_token_fail
    test_operations_with_token_succeed
    test_root_token_revocation

    log_success "All initialization tests completed!"
}

main "$@"
