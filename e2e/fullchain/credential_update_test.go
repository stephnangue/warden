//go:build e2e

package fullchain

import (
	"encoding/json"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// maskedValue is what a read substitutes for a sensitive config field. It mirrors
// maskValue in core; duplicated rather than imported because the e2e suites drive
// the API from outside and must see what a client sees.
const maskedValue = "***********"

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
// credential of its own yet. A session that already holds one is the row
// further down: it too takes up the change on its next request.
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

// TestFullChain_ResendingAMaskedConfigKeepsTheSecret drives the read-edit-resend
// flow an operator or a declarative tool actually performs: read the spec, change
// something, send the config back.
//
// A read masks sensitive config, so the caller is holding "***********" for every
// field they did not touch. Persisting that would replace the key with the mask
// and break every subsequent mint — while the write reported success and the next
// read looked identical, since the stored mask and a masked real key render the
// same. Only a request driven afterwards can tell the two apart, which is why this
// row belongs here rather than in a unit test of the merge.
//
// No masking assertion existed anywhere in the e2e suites before this row.
func TestFullChain_ResendingAMaskedConfigKeepsTheSecret(t *testing.T) {
	ensureEnv(t)

	specPath := "sys/cred/specs/" + splunkEnv.Spec()

	// Read the spec back the way a client would.
	status, body := h.APIRequest(t, "GET", specPath, leaderPort, "")
	if status != 200 {
		t.Fatalf("read spec (status %d): %s", status, body)
	}
	readConfig, ok := h.JSONPath(h.ParseJSON(t, body), "data.config").(map[string]any)
	if !ok {
		t.Fatalf("no data.config in spec read: %s", body)
	}

	// The row is only meaningful if the read really masks the key — otherwise
	// resending it would be resending the real value and prove nothing.
	if readConfig["api_key"] != maskedValue {
		t.Fatalf("api_key read back as %v, want the mask %q — this row assumes reads mask it",
			readConfig["api_key"], maskedValue)
	}

	// Send the masked config straight back, as an edit of some other field would.
	resend, err := json.Marshal(map[string]any{"config": readConfig})
	if err != nil {
		t.Fatalf("encode update: %v", err)
	}
	if status, body := h.APIRequest(t, "PUT", specPath, leaderPort, string(resend)); status != 200 {
		t.Fatalf("resend masked config (status %d): %s", status, body)
	}

	// A fresh session mints from the stored spec: the upstream must still see the
	// real key, not the mask.
	status, respBody, _ := h.ChainRequest(t, leaderPort, splunkEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         splunkEnv.CertRole(),
	})

	h.AssertChain(t, upstream, status, respBody, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + splunkKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestFullChain_LiveSessionTakesUpTheEditedSpec pins the other half: a session
// that already holds a minted credential stops sending it once the spec changes.
// A key rewritten because it leaked has to stop travelling on the next request,
// not when the session ends.
//
// The session keeps its credential across requests otherwise — the second
// request below is the cached one — so this is the edit re-keying the cache, not
// a mint on every request.
//
// Both the certificate *and* the user JWT are captured once and reused, and both
// are load-bearing: a minted credential is keyed on the agent token and the user
// token together, so re-fetching either would change the key and mint afresh.
// Calling h.FullChainUserJWT at each request site would look harmless and
// silently turn this into the row above, since every call issues a new JWT.
func TestFullChain_LiveSessionTakesUpTheEditedSpec(t *testing.T) {
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
		// The rewritten spec, not the credential the session was first issued.
		Injected:      map[string]string{"Authorization": "Bearer " + rotated},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// freshnessEnv is a mount of its own for the row below, which deletes its spec:
// deleting splunk's would leave the other rows without one if the row died midway.
var freshnessEnv = h.ProviderEnv{
	Mount:      "fc-spec-fresh",
	Type:       "dynatrace",
	URLKey:     "dynatrace_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": "fc-fresh-key-v1"},
}

// TestFullChain_RecreatedSpecReachesALiveSession: a spec deleted and created
// again under the same name is a new spec, and a session that held a credential
// minted from the old one sends the new one's on its next request.
func TestFullChain_RecreatedSpecReachesALiveSession(t *testing.T) {
	ensureEnv(t)

	cert := agentCert(t)
	user := h.FullChainUserJWT(t) // once: see the row above
	call := func(wantKey string) {
		t.Helper()
		upstream.Reset()
		status, body, _ := h.ChainRequest(t, leaderPort, freshnessEnv, h.ChainOpts{
			AgentCertPEM: cert,
			Bearer:       user,
			Role:         freshnessEnv.CertRole(),
		})
		h.AssertChain(t, upstream, status, body, h.ChainWant{
			Status:        200,
			Injected:      map[string]string{"Authorization": "Api-Token " + wantKey},
			Absent:        h.AlwaysAbsent(),
			UpstreamCalls: 1,
		})
	}
	create := func(key string) {
		t.Helper()
		payload := `{"type":"api_key","source":"` + freshnessEnv.Source() + `","config":{"api_key":"` + key + `"}}`
		if status, body := h.APIRequest(t, "POST", "sys/cred/specs/"+freshnessEnv.Spec(), leaderPort, payload); status != 201 {
			t.Fatalf("spec create: status %d, body %s", status, body)
		}
	}
	recreate := func(key string) {
		t.Helper()
		if status, body := h.APIRequest(t, "DELETE", "sys/cred/specs/"+freshnessEnv.Spec(), leaderPort, ""); status != 200 && status != 204 {
			t.Fatalf("spec delete: status %d, body %s", status, body)
		}
		create(key)
	}
	// Leave the mount as setup made it, whatever state the row died in.
	t.Cleanup(func() {
		h.APIRequest(t, "DELETE", "sys/cred/specs/"+freshnessEnv.Spec(), leaderPort, "")
		create("fc-fresh-key-v1")
	})

	call("fc-fresh-key-v1")
	call("fc-fresh-key-v1") // the session's cached credential

	recreate("fc-fresh-key-v2")
	call("fc-fresh-key-v2")
}
