#!/usr/bin/env bash

# Common test library for Warden e2e tests
# Provides utilities, assertions, and helper functions

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
WARDEN_BIN="${WARDEN_BIN:-./warden}"
WARDEN_ADDR="${WARDEN_ADDR:-http://localhost:5000}"
WARDEN_TOKEN="${WARDEN_TOKEN:-}"
SERVER_PID=""
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="$(cd "$TEST_DIR/../.." && pwd)"
TEMP_DIR=""
CONFIG_FILE=""

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

#######################################
# Logging functions
#######################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

#######################################
# Assertion functions
#######################################

assert_success() {
    local exit_code=$1
    local message="${2:-Command failed}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "$exit_code" -eq 0 ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        log_error "Assertion failed: $message (exit code: $exit_code)"
        return 1
    fi
}

assert_failure() {
    local exit_code=$1
    local message="${2:-Command should have failed but succeeded}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "$exit_code" -ne 0 ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        log_error "Assertion failed: $message"
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-Output does not contain expected string}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if echo "$haystack" | grep -qF "$needle"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        log_error "Assertion failed: $message"
        log_error "Expected to find: '$needle'"
        log_error "In output: '$haystack'"
        return 1
    fi
}

assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-Output contains unexpected string}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if ! echo "$haystack" | grep -qF "$needle"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        log_error "Assertion failed: $message"
        log_error "Did not expect to find: '$needle'"
        return 1
    fi
}

assert_equals() {
    local actual="$1"
    local expected="$2"
    local message="${3:-Values are not equal}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "$actual" = "$expected" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        log_error "Assertion failed: $message"
        log_error "Expected: '$expected'"
        log_error "Actual: '$actual'"
        return 1
    fi
}

#######################################
# Warden command execution
#######################################

run_warden() {
    local output
    local exit_code

    # Run command and capture output
    output=$("$WARDEN_BIN" "$@" 2>&1) || exit_code=$?
    exit_code=${exit_code:-0}

    # Print output
    echo "$output"

    return $exit_code
}

#######################################
# Server management
#######################################

build_warden() {
    log_info "Building warden binary..."
    cd "$PROJECT_ROOT"

    if ! go build -o warden .; then
        log_error "Failed to build warden binary"
        exit 1
    fi

    WARDEN_BIN="$PROJECT_ROOT/warden"
    log_success "Binary built: $WARDEN_BIN"
}

start_server() {
    log_info "Starting warden server..."

    # Start server in background
    "$WARDEN_BIN" server --config="$CONFIG_FILE" > "$TEMP_DIR/server.log" 2>&1 &
    SERVER_PID=$!

    log_info "Server started with PID: $SERVER_PID"

    # Give server a moment to start
    sleep 2

    # Check if server is still running
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        log_error "Server failed to start"
        cat "$TEMP_DIR/server.log"
        exit 1
    fi
}

wait_for_server() {
    log_info "Waiting for server to be ready..."

    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        if curl -sf "$WARDEN_ADDR/v1/sys/health" >/dev/null 2>&1; then
            log_success "Server is ready"
            return 0
        fi

        attempt=$((attempt + 1))
        sleep 1
    done

    log_error "Server failed to become ready after $max_attempts seconds"
    cat "$TEMP_DIR/server.log"
    exit 1
}

stop_server() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log_info "Stopping server (PID: $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        log_success "Server stopped"
    fi
}

#######################################
# Warden initialization
#######################################

init_warden() {
    log_info "Initializing warden..."

    local output
    output=$(run_warden init)

    if [ $? -ne 0 ]; then
        log_error "Failed to initialize warden"
        log_error "$output"
        exit 1
    fi

    # Extract root token from output
    WARDEN_TOKEN=$(echo "$output" | grep "^cws\." | head -n1)

    if [ -z "$WARDEN_TOKEN" ]; then
        log_error "Failed to extract root token from init output"
        log_error "$output"
        exit 1
    fi

    # Export token
    export WARDEN_TOKEN

    log_success "Warden initialized with token: ${WARDEN_TOKEN:0:20}..."
}

#######################################
# Test environment setup
#######################################

setup_test_env() {
    log_info "Setting up test environment..."

    # Set WARDEN_ADDR
    export WARDEN_ADDR

    # Create temp directory
    TEMP_DIR=$(mktemp -d)
    log_info "Temp directory: $TEMP_DIR"

    log_success "Test environment ready"
}

cleanup() {
    log_info "Cleaning up..."

    # Stop server
    stop_server

    # Remove temp directory
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        log_info "Removed temp directory"
    fi

    # Print test summary
    print_test_summary
}

print_test_summary() {
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo "Tests run: $TESTS_RUN"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo "========================================"

    if [ $TESTS_FAILED -eq 0 ]; then
        log_success "All tests passed!"
        return 0
    else
        log_error "$TESTS_FAILED test(s) failed"
        return 1
    fi
}

#######################################
# Utility functions
#######################################

extract_field_from_table() {
    local output="$1"
    local field_name="$2"

    # Extract value from table output (format: "field_name  value")
    echo "$output" | grep "^$field_name" | awk '{print $2}'
}

wait_for_condition() {
    local condition_cmd="$1"
    local timeout="${2:-30}"
    local message="${3:-Waiting for condition}"

    log_info "$message..."

    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if eval "$condition_cmd" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    log_error "Timeout waiting for condition after ${timeout}s"
    return 1
}
