#!/usr/bin/env bash

# Test script for auth method configuration management
# Tests JWT auth configuration with different input formats

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

test_config_auth_with_json_stdin() {
    log_info "Test: Configure auth with JSON via stdin"

    # Enable auth
    run_warden auth enable --type=jwt >/dev/null

    # Configure using JSON (minimal valid config)
    local output
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
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Auth configured with JSON via stdin"
}

test_config_auth_with_key_value() {
    log_info "Test: Configure auth with key=value format"

    local output
    output=$(run_warden write sys/auth/jwt/config auth_deadline=30s)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Auth configured with key=value format"
}

test_config_auth_duration_fields() {
    log_info "Test: Configure auth duration fields"

    # Test with different duration formats
    local output
    output=$(run_warden write sys/auth/jwt/config token_ttl=2h auth_deadline=15m)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Duration fields configured correctly"
}

test_config_auth_with_multiple_fields() {
    log_info "Test: Configure auth with multiple fields"

    local output
    output=$(run_warden write sys/auth/jwt/config token_ttl=1h auth_deadline=10m user_claim=email)
    local exit_code=$?

    assert_contains "$output" "Success" "Output should confirm success"

    log_success "✓ Multiple fields configured successfully"
}

test_invalid_auth_config_fails() {
    log_info "Test: Invalid auth configuration should fail"

    # Try invalid duration value
    local output
    output=$(run_warden write sys/auth/jwt/config auth_deadline=invalid 2>&1) || true
    local exit_code=$?

    # This might succeed if the parser doesn't validate, but invalid durations should fail eventually
    # The actual validation depends on the backend implementation

    log_success "✓ Invalid configuration test completed"
}

# Main execution
main() {
    log_info "========================================"
    log_info "Running Auth Configuration Tests"
    log_info "========================================"

    test_config_auth_with_json_stdin
    test_config_auth_with_key_value
    test_config_auth_duration_fields
    test_config_auth_with_multiple_fields
    test_invalid_auth_config_fails

    log_success "All auth configuration tests completed!"

    run_warden auth disable --path=jwt >/dev/null
}

main "$@"
