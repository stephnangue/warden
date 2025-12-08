#!/usr/bin/env bash

# Test script for provider configuration management
# Tests different config input formats and validation

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

test_config_with_json_stdin() {
    log_info "Test: Configure provider with JSON via stdin"

    # Enable provider
    run_warden providers enable --type=aws >/dev/null

    # Configure using JSON
    local output
    output=$(run_warden write sys/providers/aws/config <<EOF
{
  "proxy_domains": ["localhost", "warden"],
  "max_body_size": 10485760,
  "timeout": "60s"
}
EOF
)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Provider configured with JSON via stdin"
}

test_config_with_key_value() {
    log_info "Test: Configure provider with key=value format"

    local output
    output=$(run_warden write sys/providers/aws/config timeout=120s)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Provider configured with key=value format"
}

test_config_with_numeric_values() {
    log_info "Test: Configure with numeric values (type inference)"

    local output
    output=$(run_warden write sys/providers/aws/config max_body_size=20971520)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Numeric values handled correctly"
}

test_config_with_json_array() {
    log_info "Test: Configure with JSON array in key=value"

    local output
    output=$(run_warden write sys/providers/aws/config 'proxy_domains=["localhost","test"]')
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ JSON array in key=value handled correctly"
}

test_config_with_multiple_keyvalue_pairs() {
    log_info "Test: Configure with multiple key=value pairs"

    local output
    output=$(run_warden write sys/providers/aws/config max_body_size=10485760 timeout=90s)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Multiple key=value pairs handled correctly"
}

test_invalid_config_fails() {
    log_info "Test: Invalid configuration should fail with descriptive error"

    # Try to set a non-numeric value for max_body_size using JSON that will fail provider validation
    local output
    output=$(run_warden write sys/providers/aws/config <<EOF 2>&1
{
  "max_body_size": "not-a-number"
}
EOF
) || true
    local exit_code=$?

    assert_contains "$output" "failed to setup backend" "Error should mention setup failure"

    log_success "✓ Invalid configuration correctly fails with error"
}

# Main execution
main() {
    log_info "========================================"
    log_info "Running Provider Configuration Tests"
    log_info "========================================"

    test_config_with_json_stdin
    test_config_with_key_value
    test_config_with_numeric_values
    test_config_with_json_array
    test_config_with_multiple_keyvalue_pairs
    test_invalid_config_fails

    log_success "All provider configuration tests completed!"

    run_warden providers disable --path=aws >/dev/null
}

main "$@"
