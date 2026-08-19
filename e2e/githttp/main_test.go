//go:build e2e

package githttp

import (
	"crypto/ecdsa"
	"os"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The git environment is built once for the package rather than per test: setup
// mounts an auth method, a provider, a credential source and a spec, so per-test
// setup would dominate the runtime — and a test that failed mid-setup would
// leave mounts behind, turning one real failure into a cascade of 409s that
// hides it.
//
// Setup runs under sync.Once from the first test rather than from TestMain,
// because the helpers report failure with t.Fatalf: a zero-value testing.T
// cannot be used there, since Fatalf calls runtime.Goexit and deadlocks the
// process outside a test goroutine. Teardown has no such constraint.
var (
	envOnce    sync.Once
	leaderPort int
	upstream   *h.GitUpstream
	agentCAPEM string
	agentCAKey *ecdsa.PrivateKey
)

func TestMain(m *testing.M) {
	code := m.Run()
	if leaderPort != 0 {
		h.TeardownGitEnvBestEffort(leaderPort)
	}
	if upstream != nil {
		upstream.Close()
	}
	os.Exit(code)
}

// ensureEnv builds the shared environment on first use.
func ensureEnv(t *testing.T) {
	t.Helper()
	envOnce.Do(func() {
		leaderPort = h.GetLeaderPort(t)
		upstream = h.StartGitUpstream(t)
		agentCAPEM, agentCAKey = h.SetupGitEnv(t, leaderPort, upstream.URL)
	})
	if agentCAPEM == "" {
		t.Fatal("git environment is not available")
	}
	upstream.Reset()
}

// agentCert mints a client certificate for the agent leg. The common name must
// match the cert role's allowed_common_names.
func agentCert(t *testing.T) string {
	t.Helper()
	certPEM, _ := h.GenerateClientCert(t, agentCAPEM, agentCAKey, "agent-git")
	return certPEM
}

// restoreEnv puts the mount back to the package default: certificate agent, user
// leg on. Tests that repoint either must defer this so ordering cannot matter.
func restoreEnv(t *testing.T) {
	t.Helper()
	h.SetGitAgentPath(t, leaderPort, upstream.URL, "auth/cert/", h.GitUserAuthMount, "")
}
