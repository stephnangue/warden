//go:build e2e

package fullchain

import (
	"testing"
	"time"

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

	// PUT, not POST: creating a spec that already exists is a 409. The update
	// merges config rather than replacing it, which is the same thing here only
	// because splunk's spec holds api_key and nothing else — a multi-field spec
	// would need every field it wants to keep.
	write := func(v string) {
		body := `{"config":{"api_key":"` + v + `"}}`
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
// spec does not immediately stop the old secret being sent.
//
// Both the certificate *and* the user JWT are captured once and reused, and both
// are load-bearing: a minted credential is keyed on the agent token and the user
// token together, so re-fetching either would change the key and mint afresh.
// Calling h.FullChainUserJWT at each request site would look harmless and
// silently turn this into the row above, since every call issues a new JWT.
//
// What bounds the staleness is the session's own lifetime, which the row below
// checks.
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

// TestFullChain_CredentialStalenessIsBoundedBySessionTTL pins the bound an
// operator actually experiences: with the same certificate presented throughout,
// a rewritten spec takes effect once the session expires, rather than never.
//
// The row above shows a live session keeping its credential, which on its own is
// equally consistent with caching it forever — the difference between a rotation
// delayed and one that never happens. A role whose tokens last two seconds
// settles that.
//
// It pins the observable bound, not the mechanism. Once the token expires the
// next request authenticates afresh and mints under a new cache key, so a
// manager that also kept the old entry indefinitely would pass this row
// identically. Distinguishing the key becoming unreachable from the entry being
// evicted on its own TTL is an in-process question, not one a client can ask.
func TestFullChain_CredentialStalenessIsBoundedBySessionTTL(t *testing.T) {
	ensureEnv(t)

	const (
		shortRole  = "fc-splunk-shorttl"
		rotated    = "fc-splunk-rotated-after-expiry"
		sessionTTL = 2 * time.Second
	)

	// A dedicated role, so shortening the session cannot affect other rows.
	h.APIRequest(t, "DELETE", "auth/cert/role/"+shortRole, leaderPort, "")
	status, resp := h.APIRequest(t, "POST", "auth/cert/role/"+shortRole, leaderPort,
		`{"allowed_common_names":["`+h.FullChainAgentCN+`"],`+
			`"token_policies":["`+splunkEnv.Policy()+`"],`+
			`"cred_spec_name":"`+splunkEnv.Spec()+`","token_ttl":2}`)
	switch status {
	case 200, 201, 204:
	default:
		t.Fatalf("create short-TTL role (status %d): %s", status, resp)
	}
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "auth/cert/role/"+shortRole, leaderPort, "") })

	cert := agentCert(t)
	user := h.FullChainUserJWT(t)

	// Establish the session against the current spec.
	status, body, _ := h.ChainRequest(t, leaderPort, splunkEnv, h.ChainOpts{
		AgentCertPEM: cert, Bearer: user, Role: shortRole,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + splunkKey},
		UpstreamCalls: 1,
	})

	setSpecAPIKey(t, splunkEnv, rotated, splunkKey)

	// Past the session's lifetime, the cached credential can no longer be
	// reached — the token it was keyed to has expired — so the next request
	// mints against the spec as it now stands.
	time.Sleep(sessionTTL + time.Second)

	upstream.Reset()
	status, body, _ = h.ChainRequest(t, leaderPort, splunkEnv, h.ChainOpts{
		AgentCertPEM: cert, Bearer: user, Role: shortRole,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + rotated},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}
