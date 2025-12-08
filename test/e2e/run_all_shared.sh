#!/usr/bin/env bash

# Test suite runner with shared server - runs all e2e tests
# Sets up server once, runs all tests, then tears down

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
declare -a FAILED_TEST_NAMES

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

run_test() {
    local test_script="$1"
    local test_name=$(basename "$test_script" .sh)

    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    log_info "Running: $test_name"
    echo "----------------------------------------"

    # Run test with shared environment variables
    if WARDEN_TOKEN="$WARDEN_TOKEN" \
       WARDEN_ADDR="$WARDEN_ADDR" \
       WARDEN_BIN="$WARDEN_BIN" \
       SKIP_SETUP=1 \
       bash "$test_script"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
        log_success "$test_name PASSED"
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
        FAILED_TEST_NAMES+=("$test_name")
        log_error "$test_name FAILED"
    fi

    echo ""
}

print_final_summary() {
    echo ""
    echo "========================================"
    echo "       E2E Test Suite Summary"
    echo "========================================"
    echo "Total test suites: $TOTAL_TESTS"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    echo "========================================"

    if [ $FAILED_TESTS -gt 0 ]; then
        echo ""
        log_error "Failed test suites:"
        for test_name in "${FAILED_TEST_NAMES[@]}"; do
            echo "  - $test_name"
        done
        echo ""
        return 1
    else
        echo ""
        log_success "All test suites passed!"
        echo ""
        return 0
    fi
}

cleanup_env() {
    log_info "Tearing down test environment..."
    bash "$SCRIPT_DIR/teardown_once.sh"
}

main() {
    log_info "========================================"
    log_info "  Warden E2E Test Suite (Shared Server)"
    log_info "========================================"
    echo ""

    echo ""
    log_info "Running test suites..."
    echo ""

    # Run tests in order (they'll skip setup since SKIP_SETUP=1)
    run_test "$SCRIPT_DIR/test_providers.sh"
    run_test "$SCRIPT_DIR/test_provider_config.sh"
    run_test "$SCRIPT_DIR/test_auth.sh"
    run_test "$SCRIPT_DIR/test_auth_config.sh"
    run_test "$SCRIPT_DIR/test_write.sh"
    run_test "$SCRIPT_DIR/test_integration.sh"

    # Print final summary
    print_final_summary
}

main "$@"
