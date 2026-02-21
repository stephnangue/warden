# Contributing to Warden

We welcome contributions — use cases, documentation, code, bug reports, and feature requests.

## Prerequisites

- **Go 1.25.1 or later** — [Download Go](https://go.dev/dl/)
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

```bash
# Unit tests with race detection and coverage
make test-unit

# Integration tests
make test-integration
```

Coverage output is generated in `coverage.out`.

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