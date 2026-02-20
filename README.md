# Warden

**Identity-aware gateway for Cloud and SaaS services.**

Your workloads need credentials. They shouldn't have them.

Warden eliminates credential exposure by acting as an authorization proxy between your workloads and cloud services. Whether you're running AI agents, CI/CD pipelines, Terraform, or Kubernetes workloads, Warden ensures they never touch a secret while maintaining complete visibility and control.

## Key Features

### Zero Credential Exposure
Workloads never see or store credentials. Warden intercepts requests, injects short-lived credentials on-the-fly, and forwards them to cloud providers. No secrets in environment variables, no keys in config files, no credential leaks.

### Identity-Based Access
Every request is tied to a verified identity. Whether it's a CI/CD pipeline, an AI agent, a Terraform run, or a Kubernetes pod, Warden knows exactly who is making each API call.

### Just-In-Time Credentials
Credentials are minted at the moment of use and expire immediately after. No standing access, no long-lived tokens, no credential rotation headaches.

### Unified Policy Layer
One policy engine governs access to all cloud providers and services. Define who can access what resources under which conditions, replacing scattered IAM rules with a single source of truth.

### Complete Audit Trail
Every credential issuance, every API call, every action is logged with full identity context. Know exactly which workload accessed which resource, when, and why.

## Warden in the Security Ecosystem

![Warden in the security ecosystem](warden.png)

## Getting Started

### Prerequisites

- Go 1.25.1 or later
- Make

### Quick Start (Dev Mode)

Dev mode runs Warden entirely in-memory with automatic initialization and unsealing. No external dependencies required — perfect for exploring and testing.

1. **Clone and build**:
```bash
git clone https://github.com/stephnangue/warden.git
cd warden
go build -o warden ./cmd
```

2. **Start Warden in dev mode**:
```bash
./warden server --dev
```

You can also set a custom root token:
```bash
./warden server --dev --dev-root-token=my-root-token
```

3. **In another terminal, configure the client**:
```bash
export WARDEN_ADDR="http://127.0.0.1:8400"
export WARDEN_TOKEN="<root-token-from-output>"
```

4. **Explore available commands**:
```bash
./warden --help
```

> **Warning**: Dev mode stores all data in-memory. Everything is lost on restart. Do not use dev mode in production.

### Production Setup

For production, Warden requires a configuration file and external dependencies (PostgreSQL for storage, OpenBao for seal).

1. **Start dependencies** (OpenBao, PostgreSQL, etc.):
```bash
make deps-up
```

2. **Build and run with a config file**:
```bash
make brd
```

Or manually:
```bash
go build -o warden ./cmd
./warden server --config=./warden.local.hcl
```

### Configuration

Warden uses HCL configuration files. See `warden.local.hcl` for a development example covering:

- **Storage backend**: PostgreSQL or in-memory
- **Listener**: TCP or Unix socket with optional TLS
- **Providers**: Cloud and SaaS providers (AWS, Azure, Vault, GitHub, GCP, GitLab)
- **Auth methods**: JWT/OIDC for workload authentication

## Contribute to Warden

We welcome contributions! This section covers everything you need to get started.

### Prerequisites

- **Go 1.25.1 or later** - [Download Go](https://go.dev/dl/)
- **Docker and Docker Compose** - [Install Docker](https://docs.docker.com/get-docker/)
- **Make** - Pre-installed on macOS/Linux
- **Git** - [Install Git](https://git-scm.com/downloads)

### Setting Up the Development Environment

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

### Building Warden

#### Local Development

| Command | Description |
|---------|-------------|
| `make brd` | Build and run Warden (runs tests first) |
| `make brd-fast` | Build Warden (skips tests) |
| `make dev-watch` | Live development with hot reload |

#### Docker Builds

| Command | Description |
|---------|-------------|
| `make build` | Build Docker image (runs tests, uses cache) |
| `make build-fast` | Build with parallel processing |
| `make build-no-cache` | Clean build without cache |

### Running Tests

```bash
# Unit tests with race detection and coverage
make test-unit

# Integration tests
make test-integration
```

Coverage output is generated in `coverage.out`.

### Development Workflow

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

#### Database Management

| Command | Description |
|---------|-------------|
| `make warden-db-shell` | Connect to PostgreSQL |
| `make warden-db-logs` | View database logs |
| `make reset-warden-db` | Reset database (with confirmation) |

#### Viewing Logs

| Command | Description |
|---------|-------------|
| `make deps-logs` | View dependency logs |
| `make logs` | View Warden logs (Docker mode) |
| `make logs-tail` | View last 100 lines |

### Code Style Guidelines

#### Formatting
- Use Go standard formatting: `go fmt ./...`
- Run `go vet ./...` to catch common issues

#### Testing Conventions
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

### Submitting Changes

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