#!/usr/bin/env bash

# One-time setup script for running all tests
# Builds binary, starts server, and initializes once

set -euo pipefail

# Source common library
source "$(dirname "$0")/lib/common.sh"

main() {
    log_info "========================================"
    log_info "Setting up test environment (one-time)"
    log_info "========================================"

    setup_test_env

    # Build binary once
    build_warden

    # Initialize once
    init_warden

    log_success "Test environment ready!"
    log_info "Token: ${WARDEN_TOKEN:0:20}..."
    log_info ""
    log_info "Export these for running tests:"
    echo "export WARDEN_TOKEN=$WARDEN_TOKEN"
    echo "export WARDEN_ADDR=$WARDEN_ADDR"
}

main "$@"
