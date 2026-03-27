# Warden HA E2E Chaos Testing

AI-driven chaos testing for Warden's HA clustering. Uses Claude Code as an adversarial agent that continuously hypothesizes failure scenarios, executes them against a live 3-node cluster, and reports findings.

## Prerequisites

- Docker and docker-compose
- Go 1.26+
- Seal key at `seal.key`
- Claude Code CLI: `brew install --cask claude-code` ([docs](https://code.claude.com/docs/en/setup))
- `ANTHROPIC_API_KEY` environment variable set

## Quick Start

```bash
# 1. Start the 3-node cluster (includes Vault, Hydra, and PostgreSQL)
bash e2e/setup.sh

# 2. Launch the chaos testing agent
#    CLAUDE.md is auto-loaded by Claude Code when run from the e2e/ directory
cd e2e
claude --dangerously-skip-permissions "Begin the chaos testing loop"

# 3. When done, tear everything down
bash e2e/teardown.sh

# To fully reset (drop DB tables, clear root token, wipe logs) and start fresh:
bash e2e/reset.sh
bash e2e/setup.sh
```

## What setup.sh Does

1. Starts PostgreSQL, Vault, and Hydra via docker-compose (isolated `e2e-*` volumes/network)
2. Resets E2E-specific tables (`e2e_kv_store`, `e2e_ha_locks`)
3. Builds the Warden binary
4. Starts 3 nodes (ports 8500, 8510, 8520)
5. Initializes the cluster via `warden operator init`
6. Verifies 1 active leader + 2 standbys
7. Configures Vault (KV secrets, AppRole auth, policies, token roles)
8. Creates Hydra OAuth2 clients (`e2e-agent`, `e2e-pipeline`, `e2e-ephemeral`)
9. Configures Warden (Vault provider, credential source/spec, JWT auth, transparent mode)
10. Verifies Vault gateway integration end-to-end

## External Services

| Service | Address | Purpose |
|---------|---------|---------|
| PostgreSQL | `localhost:5433` | Warden HA backend (advisory locks, KV store) |
| Vault dev server | `http://127.0.0.1:8200` | Secrets backend (KV v2, AppRole, token minting) |
| Ory Hydra (public) | `http://localhost:4444` | OIDC provider for JWT issuance |
| Ory Hydra (admin) | `http://localhost:4445` | Client management |

### Vault

- Root token: `e2e-vault-root-token`
- KV v2 at `secret/` with test data at `e2e/app-config` and `e2e/database`
- AppRole auth at `e2e_approle/` for Warden credential source
- Token role `e2e-secrets-reader` for minted service tokens

### Hydra

- Issues JWT access tokens via `client_credentials` grant
- Clients: `e2e-agent` / `agent-secret`, `e2e-pipeline` / `pipeline-secret`
- Short-lived client for expired JWT testing: `e2e-ephemeral` / `ephemeral-secret` (2s TTL)

## Warden Vault Integration

The cluster mounts a **Vault provider** at `vault/` with two modes:

- **Non-transparent mode**: Authenticate with `X-Warden-Token`, Warden mints a Vault token via credential spec, proxies to Vault.
  Path: `/v1/vault/gateway/v1/<vault-path>`

- **Transparent mode**: Authenticate with `Authorization: Bearer <jwt>`, Warden validates JWT against Hydra OIDC, mints Vault credential, proxies to Vault.
  Path: `/v1/vault/role/<role>/gateway/v1/<vault-path>`

## Tools

Scripts in `e2e/tools/` for interacting with the cluster:

| Script | Usage |
|--------|-------|
| `health_check.sh [port]` | Check health of all or one node |
| `get_leader.sh` | Find the current leader |
| `kill_node.sh <1\|2\|3> [TERM\|KILL]` | Kill a node |
| `restart_node.sh <1\|2\|3>` | Restart a killed node |
| `step_down.sh [port]` | Force leader step-down |
| `api_request.sh <method> <path> [port] [body]` | Authenticated API request |
| `concurrent_requests.sh <N> <method> <path> [port]` | Fire N parallel requests |
| `collect_logs.sh [lines]` | Tail logs from all nodes |
| `assert_cluster_healthy.sh` | Assert 1 leader + 2 standbys |
| `get_jwt.sh [client_id] [client_secret]` | Fetch JWT from Hydra |
| `vault_gateway_request.sh <method> <vault_path> [port]` | Non-transparent Vault gateway request |
| `vault_transparent_request.sh <method> <vault_path> [role] [port]` | Transparent Vault gateway request (JWT) |

## Chaos Test Categories

| # | Category | Scenarios |
|---|----------|-----------|
| 1 | Leader Kill | SIGTERM/SIGKILL leader, kill during in-flight requests |
| 2 | Cascading Failure | Kill leader then new leader, kill all nodes, restart all |
| 3 | Step-Down | API step-down, step-down during in-flight requests |
| 4 | Standby Forwarding | Writes through standby, concurrent reads, health endpoint |
| 5 | Failover Consistency | Data persists across failover, deletions survive |
| 6 | Rejoin | Node rejoins after kill, rapid kill/restart cycles |
| 7 | Split-Brain Detection | Never more than 1 leader across all nodes |
| 8 | CRUD During HA | Create/delete during leader transitions |
| 9 | Vault Non-Transparent | Gateway reads/writes during failover, concurrent minting |
| 10 | Vault Transparent | JWT auth during failover, singleflight, expired/invalid JWT |
| 11 | Cross-Mode | Mixed mode requests, config survival across failover |

## Findings

The chaos agent writes findings to `e2e/findings/findings.jsonl` as JSONL with severity levels: HIGH, MEDIUM, LOW, INFO.

## Cluster Layout

| Node | API Address | Cluster Address |
|------|-------------|-----------------|
| 1 | http://127.0.0.1:8500 | https://127.0.0.1:8501 |
| 2 | http://127.0.0.1:8510 | https://127.0.0.1:8511 |
| 3 | http://127.0.0.1:8520 | https://127.0.0.1:8521 |

All nodes share the same PostgreSQL backend on port 5433 with tables `e2e_kv_store` and `e2e_ha_locks`, isolated from development tables.
