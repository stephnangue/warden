//go:build e2e

package userleg

import (
	"crypto/ecdsa"
	"os"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The user-leg environment is built once for the package rather than per test.
// Setup mounts an auth method and a provider and waits for both to settle, so
// per-test setup would dominate the runtime — and a test that failed mid-setup
// would leave mounts behind, turning one real failure into a cascade of 409s
// that hides it.
//
// Setup runs under sync.Once from the first test rather than from TestMain,
// because the helpers report failure with t.Fatalf: a zero-value testing.T
// cannot be used there, since Fatalf calls runtime.Goexit and deadlocks the
// process outside a test goroutine. Teardown has no such constraint and runs
// from TestMain on a best-effort basis.
var (
	envOnce    sync.Once
	leaderPort int
	agentCAPEM string
	agentCAKey *ecdsa.PrivateKey
)

func TestMain(m *testing.M) {
	code := m.Run()
	if leaderPort != 0 {
		h.TeardownUserLegEnvBestEffort(leaderPort)
	}
	os.Exit(code)
}

// ensureEnv builds the shared environment on first use.
func ensureEnv(t *testing.T) {
	t.Helper()
	envOnce.Do(func() {
		leaderPort = h.GetLeaderPort(t)
		agentCAPEM, agentCAKey = h.SetupUserLegEnv(t, leaderPort)
	})
	if agentCAPEM == "" {
		t.Fatal("user-leg environment is not available")
	}
}

// agentCert mints a client certificate for the agent leg.
func agentCert(t *testing.T) string {
	t.Helper()
	certPEM, _ := h.GenerateClientCert(t, agentCAPEM, agentCAKey, "agent-userleg")
	return certPEM
}

// restoreEnv puts the mount back to the package default: certificate agent,
// metadata enabled. Tests that mutate either must defer this so ordering between
// them cannot matter.
func restoreEnv(t *testing.T) {
	t.Helper()
	h.SetUserLegAgentPath(t, leaderPort, "auth/cert/", "")
	h.EnableProtectedResourceMetadata(t, leaderPort)
}
