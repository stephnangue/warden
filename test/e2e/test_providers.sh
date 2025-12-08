#!/usr/bin/env bash

# Test script for provider lifecycle management
# Tests enable, list, read, and disable operations

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

test_enable_provider_default_path() {
    log_info "Test: Enable AWS provider with default path"

    local output
    output=$(run_warden providers enable --type=aws)
    local exit_code=$?

    assert_success $exit_code "Failed to enable provider"
    assert_contains "$output" "aws" "Output should contain mount path"

    log_success "✓ Provider enabled with default path"
}

test_list_providers() {
    log_info "Test: List providers"

    local output
    output=$(run_warden providers list)
    local exit_code=$?

    assert_success $exit_code "Failed to list providers"
    assert_contains "$output" "aws" "Provider not in list"
    assert_contains "$output" "aws" "Provider type not in list"

    log_success "✓ Provider listed successfully"
}

test_read_provider() {
    log_info "Test: Read provider details"

    local output
    output=$(run_warden providers read --path=aws)
    local exit_code=$?

    assert_success $exit_code "Failed to read provider"
    assert_contains "$output" "aws" "Path not in output"
    assert_contains "$output" "aws" "Type not in output"

    log_success "✓ Provider read successfully"
}

test_enable_provider_custom_path() {
    log_info "Test: Enable provider with custom path and description"

    local output
    output=$(run_warden providers enable --type=aws --path=aws-prod --description="Production AWS")
    local exit_code=$?

    assert_success $exit_code "Failed to enable provider with custom path"

    # Verify it's listed
    output=$(run_warden providers list)
    assert_contains "$output" "aws-prod" "Custom path not in list"

    # Verify details
    output=$(run_warden providers read --path=aws-prod)
    assert_contains "$output" "aws-prod" "Path mismatch"
    assert_contains "$output" "Production AWS" "Description not found"

    log_success "✓ Provider enabled with custom path and description"
}

test_disable_provider() {
    log_info "Test: Disable provider"

    # Disable the default aws provider
    local output
    output=$(run_warden providers disable --path=aws)
    local exit_code=$?

    assert_success $exit_code "Failed to disable provider"

    # Verify it's no longer listed
    output=$(run_warden providers list)
    assert_not_contains "$output" "aws/" "Provider still in list after disable"

    log_success "✓ Provider disabled successfully"
}

test_disable_nonexistent_provider_fails() {
    log_info "Test: Disabling non-existent provider should fail"

    local output
    output=$(run_warden providers disable --path=nonexistent 2>&1) || true
    local exit_code=$?

    assert_contains "$output" "no matching mount" "Error message should indicate mount not found"

    log_success "✓ Disabling non-existent provider correctly fails"
}

test_read_nonexistent_provider_fails() {
    log_info "Test: Reading non-existent provider should fail"

    local output
    output=$(run_warden providers read --path=nonexistent 2>&1) || true
    local exit_code=$?

    assert_contains "$output" "Mount not found" "Error message should indicate mount not found"

    log_success "✓ Reading non-existent provider correctly fails"
}

test_enable_multiple_providers() {
    log_info "Test: Enable multiple providers"

    # Enable AWS at default path
    run_warden providers enable --type=aws >/dev/null

    # Enable AWS at custom path
    run_warden providers enable --type=aws --path=aws-staging >/dev/null

    # List and verify both are present
    local output
    output=$(run_warden providers list)

    assert_contains "$output" "aws/" "First provider not listed"
    assert_contains "$output" "aws-staging/" "Second provider not listed"

    log_success "✓ Multiple providers enabled successfully"
}

# Main execution
main() {
    log_info "========================================"
    log_info "Running Provider Lifecycle Tests"
    log_info "========================================"

    test_enable_provider_default_path
    test_list_providers
    test_read_provider
    test_enable_provider_custom_path
    test_disable_provider
    test_disable_nonexistent_provider_fails
    test_read_nonexistent_provider_fails
    test_enable_multiple_providers

    log_success "All provider lifecycle tests completed!"

    run_warden providers disable --path=aws >/dev/null
    run_warden providers disable --path=aws-prod >/dev/null
    run_warden providers disable --path=aws-staging >/dev/null
}

main "$@"
