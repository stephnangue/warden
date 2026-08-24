//go:build e2e

package fullchain

import (
	"crypto/ecdsa"
	"os"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Each test in this package drives one request through the whole chain — token
// extraction, role resolution, policy, mint, credential injection — and checks
// both ends against a recording upstream.
//
// Layout: one file per provider, holding that provider's environment, its
// credential constants and the rows that exist because of how *it* behaves.
// chain_test.go holds the provider-independent rows. Adding a provider is
// therefore a new file plus one line in allEnvs.
//
// The environment is built once for the package rather than per test: setup
// mounts two auth methods and, for each provider, a mount, a credential source,
// one or more specs, policies and roles. Per-test setup would dominate the
// runtime — and a test that failed mid-setup would leave mounts behind, turning
// one real failure into a cascade of 409s that hides it.
//
// Setup runs under sync.Once from the first test rather than from TestMain,
// because the helpers report failure with t.Fatalf: a zero-value testing.T
// cannot be used there, since Fatalf calls runtime.Goexit and deadlocks the
// process outside a test goroutine. Teardown has no such constraint.

// allEnvs is every provider the package sets up, in setup and teardown order.
// Between them they cover each token-extractor family — default, channels,
// channels with the native header first, scheme dispatch, and the git dual-slot
// on its REST path — and all four shared SDK credential extractors.
//
// Every provider is here. The three hand-rolled extractors — atlassian,
// honeycomb, prometheus — were absent for years of this file's life because
// their distinctive branches read credential fields nothing could supply, so a
// row could cover only the fallback each degraded to. All three are reachable
// now, and both branches of each are pinned. prometheus appears twice because
// its scheme is mount config, so covering both means two mounts.
// The four dual-mode gateways join the list from ensureEnv rather than here:
// ibmcloud's source needs the IAM stub's URL, which is not known until the stub
// is listening. Keeping all four together makes the reason legible.
var allEnvs = []h.ProviderEnv{
	openaiEnv, anthropicEnv, newrelicEnv, elasticEnv, githubEnv,
	splunkEnv, datadogEnv, restEnv, dynatraceEnv, dynatraceOAuthEnv, mcpEnv, mcpGitHubEnv,
	mcpAWSEnv, mcpAWSWrongCredEnv, atlassianEnv, honeycombEnv,
	prometheusEnv, prometheusBasicEnv,
	scalewayEnv, cloudflareEnv, ovhEnv,
	vaultEnv,
}

var (
	envOnce    sync.Once
	envReady   bool
	leaderPort int
	upstream   *h.RecordingUpstream
	agentCAPEM string
	agentCAKey *ecdsa.PrivateKey
)

func TestMain(m *testing.M) {
	code := m.Run()
	if leaderPort != 0 {
		for _, env := range allEnvs {
			h.TeardownFullChainProviderBestEffort(leaderPort, env)
		}
		// Removes the namespace and everything mounted inside it. Deleting a
		// namespace is asynchronous, which is why it is built once per package
		// rather than per test.
		teardownNamespaceEnvBestEffort(leaderPort)
		h.TeardownFullChainCommonBestEffort(leaderPort)
	}
	if upstream != nil {
		upstream.Close()
	}
	if ibmIAMStub != nil {
		ibmIAMStub.Close()
	}
	os.Exit(code)
}

// ensureEnv builds the shared environment on first use.
func ensureEnv(t *testing.T) {
	t.Helper()
	envOnce.Do(func() {
		leaderPort = h.GetLeaderPort(t)
		upstream = h.StartRecordingUpstream(t)

		// ibmcloud mints by exchanging an API key at IBM's IAM endpoint, a
		// vendor-specific grant no general-purpose issuer serves, so a stub
		// stands in. Its URL is source config, hence the env is built here.
		ibmIAMStub = startIBMIAMStub()
		ibmcloudEnv = buildIBMCloudEnv(ibmIAMStub.URL)
		allEnvs = append(allEnvs, ibmcloudEnv)

		// vault's source is the one that authenticates against something real: it
		// verifies its AppRole role and logs in while being created, so the role
		// has to exist in Vault before the setup loop reaches that mount.
		seedVaultApproleRole(t, vaultApproleRole, vaultRoleID, vaultSecretID)

		agentCAPEM, agentCAKey = h.SetupFullChainCommon(t, leaderPort)
		for _, env := range allEnvs {
			h.SetupFullChainProvider(t, leaderPort, upstream.URL, env)
		}
		// Last statement, so a setup that fatals partway leaves this false. A
		// t.Fatalf inside the closure unwinds via runtime.Goexit, which still
		// marks the Once done — without this flag every later test would run
		// against a half-built environment and fail with unrelated 404s, burying
		// the one failure that mattered.
		envReady = true
	})
	if !envReady {
		t.Fatal("full-chain environment is not available")
	}
	// Recorded traffic is per-test: one test's requests must never be readable
	// as another's, and the assertions count requests exactly.
	upstream.Reset()
}

// agentCert mints a client certificate for the agent leg. The common name must
// match the cert roles' allowed_common_names.
func agentCert(t *testing.T) string {
	t.Helper()
	certPEM, _ := h.GenerateClientCert(t, agentCAPEM, agentCAKey, h.FullChainAgentCN)
	return certPEM
}

// useJWTAgentLeg repoints a mount to authenticate agents by bearer token for the
// duration of one test.
//
// A certificate is only one of the ways an agent can arrive beside a user; the
// rest carry a token in a header, and a mount whose agent leg is auth/cert
// cannot validate one. Tests using this present the agent and the user as
// different clients — identical credentials in both slots are rejected outright,
// and would prove nothing about attribution either way.
func useJWTAgentLeg(t *testing.T, p h.ProviderEnv) {
	t.Helper()
	h.SetFullChainLegs(t, leaderPort, upstream.URL, p, h.JWTAgentPath, h.FullChainUserAuthMount)
	t.Cleanup(func() { h.ResetFullChainLegs(t, leaderPort, upstream.URL, p) })
}
