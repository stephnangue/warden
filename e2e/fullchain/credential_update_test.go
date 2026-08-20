//go:build e2e

package fullchain

import (
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Whether a configuration change reaches the request path is its own class of
// question, separate from whether the change was stored. A compiled-policy cache
// once answered it wrongly — the API returned the new policy while the old one
// was enforced — so the same question is worth asking of credentials, where the
// stakes are the same: a key rotated because it leaked is only rotated if
// requests stop carrying the old one.

// setSpecAPIKey rewrites a spec's api_key, restoring the original afterwards so
// the mount is left as the other rows expect to find it.
func setSpecAPIKey(t *testing.T, env h.ProviderEnv, key, restore string) {
	t.Helper()

	write := func(v string) {
		body := `{"type":"api_key","source":"` + env.Source() + `","config":{"api_key":"` + v + `"}}`
		status, resp := h.APIRequest(t, "PUT", "sys/cred/specs/"+env.Spec(), leaderPort, body)
		switch status {
		case 200, 201, 204:
		default:
			t.Fatalf("rewrite spec %s (status %d): %s", env.Spec(), status, resp)
		}
	}

	write(key)
	t.Cleanup(func() { write(restore) })
}

// TestFullChain_UpdatedSpecReachesUpstream checks that rewriting a credential
// spec changes what a new session sends upstream.
//
// The agent presents a fresh certificate, so this is a new session with no
// credential of its own yet — the case that must always reflect current
// configuration. A minted credential is cached per session, so an existing
// session legitimately keeps the credential it was issued; that bound is the
// subject of the row below, and the two together say when a rotation takes
// effect.
func TestFullChain_UpdatedSpecReachesUpstream(t *testing.T) {
	ensureEnv(t)

	const rotated = "fc-splunk-rotated-not-a-real-key"
	setSpecAPIKey(t, splunkEnv, rotated, splunkKey)

	status, body, _ := h.ChainRequest(t, leaderPort, splunkEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         splunkEnv.CertRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + rotated},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestFullChain_LiveSessionKeepsItsCredential pins the other half: a session that
// already holds a minted credential keeps using it after the spec changes.
//
// This is deliberate — a credential is issued to a session, and re-minting on
// every request would defeat the point of issuing one — but it is the part
// operators are most likely to be surprised by, because it means rewriting a
// spec does not immediately stop the old secret being sent. What bounds the
// staleness is the session's own lifetime.
//
// Both requests reuse one certificate, which is what makes them one session; the
// row above mints a fresh one precisely to be a different session.
func TestFullChain_LiveSessionKeepsItsCredential(t *testing.T) {
	ensureEnv(t)

	cert := agentCert(t)
	user := h.FullChainUserJWT(t)

	// Establish the session, and confirm what it currently carries.
	status, body, _ := h.ChainRequest(t, leaderPort, splunkEnv, h.ChainOpts{
		AgentCertPEM: cert,
		Bearer:       user,
		Role:         splunkEnv.CertRole(),
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + splunkKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	const rotated = "fc-splunk-rotated-mid-session"
	setSpecAPIKey(t, splunkEnv, rotated, splunkKey)

	upstream.Reset()
	status, body, _ = h.ChainRequest(t, leaderPort, splunkEnv, h.ChainOpts{
		AgentCertPEM: cert,
		Bearer:       user,
		Role:         splunkEnv.CertRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status: 200,
		// The credential issued to this session, not the rewritten spec.
		Injected:      map[string]string{"Authorization": "Bearer " + splunkKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}
