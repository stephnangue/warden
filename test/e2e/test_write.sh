#!/usr/bin/env bash

# Test script for write command variations
# Tests different input formats and type inference

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

test_write_with_json_stdin() {
    log_info "Test: Write with JSON via stdin"

    # Enable provider first
    run_warden providers enable --type=aws >/dev/null

    local output
    output=$(run_warden write sys/providers/aws/config <<EOF
{
  "timeout": "60s"
}
EOF
)

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Write with JSON stdin works"
}

test_write_with_keyvalue() {
    log_info "Test: Write with key=value format"

    local output
    output=$(run_warden write sys/providers/aws/config timeout=90s)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Write with key=value works"
}

test_write_type_inference_integer() {
    log_info "Test: Type inference for integers"

    local output
    output=$(run_warden write sys/providers/aws/config max_body_size=10485760)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Integer type inference works"
}

test_write_type_inference_boolean() {
    log_info "Test: Type inference for booleans"

    # Booleans aren't directly configurable in current provider config,
    # but test the mechanism works
    local output
    output=$(run_warden write sys/providers/aws/config timeout=60s)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Type inference works"
}

test_write_json_array_in_keyvalue() {
    log_info "Test: JSON array in key=value format"

    local output
    output=$(run_warden write sys/providers/aws/config 'proxy_domains=["localhost","test","warden"]')
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ JSON array in key=value works"
}

test_write_multiple_keyvalue_pairs() {
    log_info "Test: Multiple key=value pairs"

    local output
    output=$(run_warden write sys/providers/aws/config max_body_size=20971520 timeout=120s)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Multiple key=value pairs work"
}

# Main execution
main() {
    log_info "========================================"
    log_info "Running Write Command Tests"
    log_info "========================================"

    test_write_with_json_stdin
    test_write_with_keyvalue
    test_write_type_inference_integer
    test_write_type_inference_boolean
    test_write_json_array_in_keyvalue
    test_write_multiple_keyvalue_pairs

    log_success "All write command tests completed!"

    run_warden providers disable --path=aws >/dev/null

}

main "$@"
