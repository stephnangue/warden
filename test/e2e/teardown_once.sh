#!/usr/bin/env bash

# Teardown script to clean up after all tests

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

main() {
    log_info "Cleaning up test environment..."

    # Use exported values if available
    SERVER_PID="${TEST_SERVER_PID:-}"
    TEMP_DIR="${TEST_TEMP_DIR:-}"

    cleanup

    log_success "Test environment cleaned up!"
}

main "$@"
