# Warden End-to-End Tests

Comprehensive end-to-end CLI tests for Warden that validate provider and auth management functionality through the actual CLI binary.

## Overview

These tests verify the complete CLI workflow including:
- Initialization and root token management
- Provider lifecycle (enable, configure, list, read, disable)
- Auth method lifecycle (enable, configure, list, read, disable)
- Configuration management (JSON stdin, key=value, type inference)
- Integration workflows

## Directory Structure

```
test/
├── e2e/
│   ├── lib/
│   │   └── common.sh          # Common test utilities and assertions
│   ├── test_init.sh           # Initialization tests
│   ├── test_providers.sh      # Provider lifecycle tests
│   ├── test_provider_config.sh # Provider configuration tests
│   ├── test_auth.sh           # Auth method lifecycle tests
│   ├── test_auth_config.sh    # Auth configuration tests
│   ├── test_write.sh          # Write command tests
│   ├── test_integration.sh    # Integration workflow tests
│   ├── run_all.sh             # Test suite runner (isolated)
│   ├── run_all_shared.sh      # Test suite runner (shared server - faster)
│   ├── setup_once.sh          # One-time setup for manual testing
│   └── teardown_once.sh       # Cleanup for manual testing
├── fixtures/
│   ├── provider_config.json   # Sample provider configs
│   └── auth_config.json       # Sample auth configs
├── README.md                  # This file
└── E2E_USAGE.md              # Quick usage guide
```

## Prerequisites

- Go 1.21+ installed
- Bash shell
- `curl` command available
- Network access to localhost:5000

## Running Tests

### Run All Tests (Recommended - Shared Server Mode)

**Fastest option** - builds once, starts one server, runs all tests:

```bash
# Using Makefile (recommended)
make test-e2e

# Or directly
./test/e2e/run_all_shared.sh
```

### Run All Tests (Isolated Mode)

Each test suite starts its own server (slower but fully isolated):

```bash
# Using Makefile
make test-e2e-isolated

# Or directly
./test/e2e/run_all.sh
```

### Run Individual Test Suites

```bash
# Initialization tests
make test-e2e-init
# or
./test/e2e/test_init.sh

# Provider lifecycle tests
make test-e2e-providers
# or
./test/e2e/test_providers.sh

# Provider configuration tests
make test-e2e-provider-config
# or
./test/e2e/test_provider_config.sh

# Auth lifecycle tests
make test-e2e-auth
# or
./test/e2e/test_auth.sh

# Auth configuration tests
make test-e2e-auth-config
# or
./test/e2e/test_auth_config.sh

# Write command tests
make test-e2e-write
# or
./test/e2e/test_write.sh

# Integration tests
make test-e2e-integration
# or
./test/e2e/test_integration.sh
```

## Test Categories

### 1. Initialization Tests (`test_init.sh`)

Tests warden initialization and token management:
- Server health check
- Root token generation via `warden init`
- Token format validation (cws.* prefix)
- Re-initialization prevention
- Operations without token fail
- Root token revocation and regeneration

### 2. Provider Lifecycle Tests (`test_providers.sh`)

Tests provider mount/unmount operations:
- Enable provider with default path
- Enable provider with custom path
- Enable provider with description
- List providers
- Read provider details
- Disable provider
- Error handling for non-existent providers
- Multiple providers concurrently

### 3. Provider Configuration Tests (`test_provider_config.sh`)

Tests provider configuration with various input formats:
- Configure with JSON via stdin
- Configure with key=value format
- Type inference for numeric values
- JSON arrays in key=value format
- Multiple key=value pairs
- Invalid configuration error handling

### 4. Auth Method Lifecycle Tests (`test_auth.sh`)

Tests auth method mount/unmount operations:
- Enable auth with default path
- Enable auth with custom path
- Enable auth with description
- List auth methods
- Read auth details
- Disable auth method
- Error handling for non-existent auth methods
- Multiple auth methods concurrently

### 5. Auth Configuration Tests (`test_auth_config.sh`)

Tests auth method configuration:
- Configure with JSON via stdin
- Configure with key=value format
- Duration field handling (token_ttl, auth_deadline)
- Multiple configuration fields
- Invalid configuration handling

### 6. Write Command Tests (`test_write.sh`)

Tests the write command with various input formats:
- JSON via stdin
- Key=value pairs
- Type inference (integers, floats, booleans, strings)
- JSON arrays in key=value format
- Multiple key=value pairs
- Writing to system paths

### 7. Integration Tests (`test_integration.sh`)

Tests complete end-to-end workflows:
- Full provider workflow (enable → configure → read → disable)
- Full auth workflow (enable → configure → read → disable)
- Concurrent providers and auth methods
- Root token revocation and regeneration workflow

## Test Features

### Automatic Server Management

Each test:
1. Builds the warden binary (if needed)
2. Starts a test server in the background
3. Waits for server to be ready
4. Runs tests
5. Cleans up server and temporary files on exit

### Comprehensive Assertions

The test library provides:
- `assert_success` - Assert command succeeded
- `assert_failure` - Assert command failed
- `assert_contains` - Assert output contains string
- `assert_not_contains` - Assert output doesn't contain string
- `assert_equals` - Assert values are equal

### Test Isolation

- Each test suite runs independently
- Tests use temporary directories
- Server runs in isolated environment
- Tests clean up after themselves

## Environment Variables

The tests respect these environment variables:

- `WARDEN_BIN` - Path to warden binary (default: ./warden)
- `WARDEN_ADDR` - Server address (default: http://localhost:5000)
- `WARDEN_TOKEN` - Auth token (set automatically by tests)

## Test Output

Tests provide colored output:
- **Blue** - Informational messages
- **Green** - Success messages
- **Red** - Error messages
- **Yellow** - Warning messages

Example output:
```
========================================
Running Provider Lifecycle Tests
========================================

[INFO] Setting up test environment...
[INFO] Building warden binary...
[SUCCESS] Binary built: /path/to/warden
[INFO] Starting warden server...
[INFO] Server started with PID: 12345
[INFO] Waiting for server to be ready...
[SUCCESS] Server is ready
[INFO] Initializing warden...
[SUCCESS] Warden initialized with token: cws.2137...

[INFO] Test: Enable AWS provider with default path
[SUCCESS] ✓ Provider enabled with default path

[INFO] Test: List providers
[SUCCESS] ✓ Provider listed successfully

...

========================================
Test Summary
========================================
Tests run: 8
Passed: 8
Failed: 0
========================================

[SUCCESS] All tests passed!
```

## Troubleshooting

### Tests Fail to Start Server

If the server fails to start, check:
- Port 5000 is not already in use
- Go is installed and in PATH
- Build errors in server.log (created in temp directory)

### Tests Fail Due to Timeout

If tests timeout waiting for server:
- Increase timeout in `lib/common.sh` (currently 30 seconds)
- Check server logs for startup errors
- Verify network connectivity to localhost

### Permission Denied Errors

Ensure test scripts are executable:
```bash
chmod +x test/e2e/*.sh test/e2e/lib/*.sh
```

### Binary Build Failures

If the warden binary fails to build:
- Run `go build` manually to see detailed errors
- Ensure all dependencies are available (`go mod download`)
- Check Go version (requires 1.21+)

## Contributing

When adding new tests:

1. Follow the existing test structure
2. Use the common library for assertions
3. Add test to `run_all.sh`
4. Document the test in this README
5. Ensure tests are idempotent
6. Clean up resources properly

## CI/CD Integration

These tests are designed to run in CI environments:

```yaml
# Example GitHub Actions workflow
- name: Run E2E Tests
  run: make test-e2e
```

The tests:
- Exit with non-zero code on failure
- Produce clear output for CI logs
- Don't require manual intervention
- Run in isolated environment

## Future Enhancements

Potential improvements:
- [ ] Parallel test execution
- [ ] Test coverage metrics
- [ ] Performance benchmarks
- [ ] Multi-server scenarios
- [ ] TLS/HTTPS testing
- [ ] Authentication flow testing (login)
- [ ] More complex configuration scenarios
