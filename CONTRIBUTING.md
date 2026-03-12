# Contributing to Warden

We welcome contributions — use cases, documentation, code, bug reports, and feature requests.

## Prerequisites

- **Go 1.26.1 or later** — [Download Go](https://go.dev/dl/)
- **Docker and Docker Compose** — [Install Docker](https://docs.docker.com/get-docker/)
- **Make** — Pre-installed on macOS/Linux
- **Git** — [Install Git](https://git-scm.com/downloads)

## Setting Up the Development Environment

1. **Fork and clone the repository**:

```bash
git clone https://github.com/YOUR_USERNAME/warden.git
cd warden
git remote add upstream https://github.com/stephnangue/warden.git
```

2. **Start development dependencies**:

```bash
make deps-up
```

3. **Verify your setup**:

```bash
make brd-fast
```

## Building Warden

### Local Development

| Command | Description |
|---------|-------------|
| `make brd` | Build and run Warden (runs tests first) |
| `make brd-fast` | Build Warden (skips tests) |
| `make dev-watch` | Live development with hot reload |

### Docker Builds

| Command | Description |
|---------|-------------|
| `make build` | Build Docker image (runs tests, uses cache) |
| `make build-fast` | Build with parallel processing |
| `make build-no-cache` | Clean build without cache |

## Running Tests

### Unit Tests

```bash
# Unit tests with race detection and coverage
make test-unit
```

Coverage output is generated in `coverage.out`.

### End-to-End Tests

E2E tests run against a live 3-node HA cluster with Vault, Hydra, and PostgreSQL.

| Command | Description |
|---------|-------------|
| `make test-e2e` | Start the cluster, run all e2e tests, tear down |
| `make test-e2e-setup` | Start the e2e cluster only |
| `make test-e2e-teardown` | Stop the e2e cluster |
| `make test-e2e-reset` | Reset and restart the e2e cluster |

To run a specific test suite or single test against an already-running cluster:

```bash
make test-e2e-setup
go test -tags e2e -v ./e2e/forwarding/
go test -tags e2e -run TestSigV4ThroughStandbyForwarding ./e2e/forwarding/ -v
make test-e2e-teardown
```

#### E2E Test Suites

| Package | Focus |
|---------|-------|
| `e2e/cluster` | Split-brain detection |
| `e2e/ha` | Leader election, step-down, failover, node rejoin |
| `e2e/forwarding` | Standby-to-leader request forwarding, SigV4 preservation |
| `e2e/provider` | Vault transparent/non-transparent gateway, JWT validation |
| `e2e/credential` | Credential issuance, caching, TTL expiry, cross-namespace |
| `e2e/rotation` | Credential source rotation, activation delay, failover persistence |
| `e2e/namespace` | Namespace CRUD and isolation |
| `e2e/seal` | Seal/unseal operations |
| `e2e/auth` | JWT/cert authentication flows, cert auth CLI (flags, env vars, mTLS, privilege escalation), auto_auth_path validation |
| `e2e/audit` | Audit logging |
| `e2e/concurrency` | Concurrent request handling |

#### Writing E2E Tests

- Use the `//go:build e2e` build tag
- Import helpers: `h "github.com/stephnangue/warden/e2e/helpers"`
- Use `h.GetLeaderPort(t)` and `h.GetStandbyPort(t)` to discover cluster topology
- Register cleanup via `t.Cleanup` **before** creating resources to avoid orphans on partial failure
- Accept `409` (conflict) in setup to be idempotent across test reruns
- Use `h.GetLeaderPort(t)` at cleanup time (not a captured port) to handle leader changes

See [e2e/README.md](e2e/README.md) for full cluster architecture and configuration details.

## Development Workflow

1. **Start dependencies**:

```bash
make deps-up
```

2. **Use hot reload for fast iteration**:

```bash
make dev-watch
```

3. **Or manually build and run**:

```bash
make brd-fast
./warden server --config=./warden.local.hcl
```

### Database Management

| Command | Description |
|---------|-------------|
| `make warden-db-shell` | Connect to PostgreSQL |
| `make warden-db-logs` | View database logs |
| `make reset-warden-db` | Reset database (with confirmation) |

### Viewing Logs

| Command | Description |
|---------|-------------|
| `make deps-logs` | View dependency logs |
| `make logs` | View Warden logs (Docker mode) |
| `make logs-tail` | View last 100 lines |

## Code Style Guidelines

### Formatting

- Use Go standard formatting: `go fmt ./...`
- Run `go vet ./...` to catch common issues

### Testing Conventions

- Use **table-driven tests** for comprehensive coverage
- Include **descriptive test case names**
- Test edge cases (nil inputs, empty values, boundary conditions)

Example:

```go
func TestFunctionName(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {
            name:     "valid input returns expected output",
            input:    "test",
            expected: "result",
            wantErr:  false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := FunctionName(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            assert.NoError(t, err)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

## Submitting Changes

1. **Create a feature branch**:

```bash
git fetch upstream
git checkout main
git merge upstream/main
git checkout -b feature/your-feature-name
```

2. **Make your changes** with tests

3. **Run tests**:

```bash
make test-unit
```

4. **Commit with a descriptive message**:

```bash
git commit -m "Add support for Azure provider

- Implement credential management
- Add request signing
- Include unit tests"
```

5. **Push and create a Pull Request**:

```bash
git push origin feature/your-feature-name
```