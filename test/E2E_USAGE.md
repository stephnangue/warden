# End-to-End Test Usage

## Quick Start

### Run All Tests (Recommended - Fast)

This builds the binary once, starts one server, initializes once, and runs all tests against the shared server:

```bash
make test-e2e
# or
./test/e2e/run_all_shared.sh
```

### Run All Tests (Isolated - Slower)

Each test suite starts its own server (slower but fully isolated):

```bash
make test-e2e-isolated
# or
./test/e2e/run_all.sh
```

## Individual Test Suites

Run specific test suites individually (each starts its own server):

```bash
# Provider tests
make test-e2e-providers
./test/e2e/test_providers.sh

# Provider configuration tests
make test-e2e-provider-config
./test/e2e/test_provider_config.sh

# Auth tests
make test-e2e-auth
./test/e2e/test_auth.sh

# Auth configuration tests
make test-e2e-auth-config
./test/e2e/test_auth_config.sh

# Write command tests
make test-e2e-write
./test/e2e/test_write.sh

# Integration tests
make test-e2e-integration
./test/e2e/test_integration.sh

# Init tests
make test-e2e-init
./test/e2e/test_init.sh
```

## Manual Setup (Advanced)

For debugging or running tests manually against a persistent server:

### 1. Setup Once

```bash
# Build binary, start server, and initialize
./test/e2e/setup_once.sh

# This will output environment variables to export:
export WARDEN_TOKEN=cws.xxxxx...
export WARDEN_ADDR=http://localhost:5000
export WARDEN_BIN=/path/to/warden
export TEST_SERVER_PID=12345
export TEST_TEMP_DIR=/tmp/xxx
```

### 2. Run Tests

```bash
# Run individual tests with shared environment
SKIP_SETUP=1 ./test/e2e/test_providers.sh
SKIP_SETUP=1 ./test/e2e/test_auth.sh
# etc...
```

### 3. Teardown

```bash
# Clean up server and temp files
./test/e2e/teardown_once.sh
```

## Test Modes

### Shared Server Mode (Fast)
- **Command**: `make test-e2e` or `./test/e2e/run_all_shared.sh`
- **Pros**: Much faster, builds once, single server
- **Cons**: Tests share state (may need cleanup between tests)
- **Best for**: Quick validation, CI/CD

### Isolated Mode (Slower)
- **Command**: `make test-e2e-isolated` or `./test/e2e/run_all.sh`
- **Pros**: Complete isolation, no state sharing
- **Cons**: Slower, builds/starts server for each suite
- **Best for**: Debugging, ensuring test independence

## Environment Variables

Tests respect these variables:

- `WARDEN_BIN` - Path to warden binary (default: ./warden)
- `WARDEN_ADDR` - Server address (default: http://localhost:5000)
- `WARDEN_TOKEN` - Auth token (auto-set by init)
- `SKIP_SETUP` - Set to 1 to skip server setup
- `TEST_SERVER_PID` - Server process ID for cleanup
- `TEST_TEMP_DIR` - Temporary directory for test files

## Examples

### Run all tests (shared server)
```bash
make test-e2e
```

### Run only provider tests
```bash
make test-e2e-providers
```

### Debug a specific test
```bash
# Start server manually
./test/e2e/setup_once.sh
export WARDEN_TOKEN=... # from output above

# Run test with debugging
SKIP_SETUP=1 bash -x ./test/e2e/test_providers.sh

# Clean up
./test/e2e/teardown_once.sh
```

### Run against existing server
```bash
# If you already have a server running:
export WARDEN_ADDR=http://localhost:5000
export WARDEN_TOKEN=cws.your-token-here
export WARDEN_BIN=./warden
export SKIP_SETUP=1

# Run tests
./test/e2e/test_providers.sh
```

## Troubleshooting

### Port Already in Use
If port 5000 is already in use:
```bash
# Find and kill the process
lsof -ti:5000 | xargs kill -9

# Or change the port
export WARDEN_ADDR=http://localhost:5001
# Update config.hcl accordingly
```

### Tests Hang
If tests hang waiting for server:
- Check server logs in temp directory
- Increase timeout in `lib/common.sh`
- Verify server actually started (check PID)

### Permission Errors
```bash
chmod +x test/e2e/*.sh test/e2e/lib/*.sh
```

### Server Won't Start
- Check if binary built correctly: `./warden version`
- Check logs in temp directory
- Verify Go version: `go version` (requires 1.21+)
