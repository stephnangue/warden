//go:build e2e

package userleg

import (
	"strings"
	"testing"
	"time"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// =============================================================================
// Agent-user binding
// =============================================================================
//
// The user leg proves who the human is. A binding additionally ties that human
// to the agent acting for them, so an agent cannot pair itself with any user
// token it happens to obtain.
//
// The decision can be made at the IdP — attested cryptographically on the user's
// token — and enforced here per request; or, where the IdP has decided nothing,
// decided and enforced here in one step. Either way the gateway compares a value
// carried on the user's token against the agent actually presenting the request.
// These tests run the second case; SetupUserLegBinding explains why and what it
// leaves to unit coverage.
//
// This is the only place the whole chain runs: a claim on a real IdP-issued
// token, through the role's metadata_claims, into a CEL condition evaluated
// against the live agent. The unit tests fabricate req.User by hand and start at
// the CEL layer, so they cannot catch a break in captureUserContext, in the
// claim mapping, or in the order the two principals are resolved.

// bindingEnv installs the binding fixture and returns the identity the user's
// mapped claim carries, read off the token the IdP actually issued.
func bindingEnv(t *testing.T) string {
	t.Helper()
	ensureEnv(t)
	actingAgent := h.JWTSubject(t, h.UserJWT(t))
	h.SetupUserLegBinding(t, leaderPort, actingAgent)
	t.Cleanup(func() { h.TeardownUserLegBinding(t, leaderPort) })
	return actingAgent
}

// TestBinding_MatchingAgentAllowed is the case the binding exists to permit: the
// agent the user's token names is the agent presenting the request.
//
// The certificate CN is derived from the token rather than hardcoded. A literal
// would make this pass or fail on whether it still matches what the IdP issues,
// which is not what is under test.
func TestBinding_MatchingAgentAllowed(t *testing.T) {
	actingAgent := bindingEnv(t)

	cert, _ := h.GenerateClientCert(t, agentCAPEM, agentCAKey, actingAgent)
	status, body := h.UserLegRequestAs(t, leaderPort, h.UserLegBoundRole, cert,
		map[string]string{"Authorization": "Bearer " + h.UserJWT(t)})

	if status != 200 {
		t.Fatalf("agent %q matches the user's claim and must be allowed, got %d: %s",
			actingAgent, status, string(body))
	}
}

// TestBinding_MismatchedAgentDenied is the case it exists to refuse: same user
// token, different agent.
//
// Both cert roles carry the same policy and the same capabilities, so a denial
// here can only come from the condition. Had they differed in authorization this
// would pass for the wrong reason — and keep passing with the binding removed.
//
// It stays 403 while TestBinding_MissingUserChallenged is a 401, and together
// they pin the whole progression: challenged while the client has no user,
// forbidden once it has one that does not match. A 401 here would loop a client
// that has already done everything asked of it.
func TestBinding_MismatchedAgentDenied(t *testing.T) {
	bindingEnv(t)

	// CN "agent-userleg": a legitimate agent, just not this user's.
	status, body := h.UserLegRequestAs(t, leaderPort, h.UserLegUnboundRole, agentCert(t),
		map[string]string{"Authorization": "Bearer " + h.UserJWT(t)})

	if status == 200 {
		t.Fatalf("a user token naming another agent must not be accepted, got 200: %s", string(body))
	}
	if status != 403 {
		t.Errorf("expected a policy denial (403), got %d: %s", status, string(body))
	}
}

// TestBinding_MissingUserChallenged covers `user.present`, and is where the
// binding's bootstrap lives.
//
// A user credential is optional on a protected-resource mount: some paths need
// one, others do not, and the client cannot know which. So a request arriving
// without one is well-formed — the client did nothing wrong. Answering 403 would
// end the exchange there, because no client stack begins discovery on a 403.
// The 401 names where to acquire a user, which is the only way the client can
// ever learn that this path wants one.
//
// Uses the same certificate that succeeds in TestBinding_MatchingAgentAllowed,
// so the only difference is the missing Authorization header.
func TestBinding_MissingUserChallenged(t *testing.T) {
	actingAgent := bindingEnv(t)

	cert, _ := h.GenerateClientCert(t, agentCAPEM, agentCAKey, actingAgent)
	status, _, hdrs := h.DoRequestWithResponseHeaders(t, "GET",
		h.NodeURL(leaderPort)+"/v1/"+h.UserLegMount+"/gateway/v1/secret/data/e2e/app-config",
		map[string]string{
			"X-Warden-Role":     h.UserLegBoundRole,
			"X-SSL-Client-Cert": h.URLEncodePEM(cert),
		}, "")

	if status != 401 {
		t.Fatalf("a bound path with no user must challenge, not merely forbid; got %d", status)
	}

	challenge := challengeOf(t, hdrs)
	if !strings.Contains(challenge, "resource_metadata=") {
		t.Fatalf("the challenge must name where to authenticate: %q", challenge)
	}
	if strings.Contains(challenge, "invalid_token") {
		t.Errorf("no credential was presented, so none can be invalid: %q", challenge)
	}

	// The link has to resolve, or the bootstrap dies one step later.
	url := extractResourceMetadata(t, challenge)
	if fetchStatus, _ := h.DoRequest(t, "GET", url, nil, ""); fetchStatus != 200 {
		t.Fatalf("challenge named %s, which returned %d", url, fetchStatus)
	}

	assertChallengeAudited(t, leaderPort)
}

// assertChallengeAudited pins that the audit log agrees with the wire.
//
// A denial is audited twice — once inside the deny branch and once by the
// caller — and the first entry takes its status from the response object as it
// stands at that moment. Build the challenge after that entry instead of before
// and the log records 403 while the client received 401, with nothing in either
// place revealing the disagreement. Every wire-level assertion above still
// passes in that state, so this is the only thing standing between that bug and
// production.
//
// Both entries must also carry user_absent, since that is what explains how a
// "permission denied" decision produced a 401 rather than a 403.
func assertChallengeAudited(t *testing.T, port int) {
	t.Helper()
	nodeNum := h.NodeNumberForPort(port)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var seen int
		for _, e := range h.ReadAuditEntries(t, nodeNum, h.UserLegMount) {
			if e.Type != "response" || e.Auth == nil || e.Auth.PolicyResults == nil {
				continue
			}
			cond := e.Auth.PolicyResults.Condition
			if cond == nil || !cond.UserAbsent {
				continue
			}
			seen++
			if e.Response == nil || e.Response.StatusCode != 401 {
				got := 0
				if e.Response != nil {
					got = e.Response.StatusCode
				}
				t.Fatalf("audited status %d disagrees with the 401 sent to the client", got)
			}
		}
		if seen > 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Error("no audited response recorded the user-absent denial")
}

// TestBinding_UnmappedClaimDenies is the fail-closed property that makes the
// binding safe to rely on. Removing the claim mapping — the misconfiguration an
// operator is most likely to make — must deny, because the condition then reads
// a metadata key that no longer exists.
func TestBinding_UnmappedClaimDenies(t *testing.T) {
	actingAgent := bindingEnv(t)

	// Drop metadata_claims, leaving everything else in place.
	h.SetUserLegClaimMapping(t, leaderPort, false)

	cert, _ := h.GenerateClientCert(t, agentCAPEM, agentCAKey, actingAgent)
	status, body := h.UserLegRequestAs(t, leaderPort, h.UserLegBoundRole, cert,
		map[string]string{"Authorization": "Bearer " + h.UserJWT(t)})

	if status == 200 {
		t.Fatalf("an unmapped claim must fail closed, not pass: %s", string(body))
	}
}

// TestBinding_AuditRecordsBothSides is why the binding compares a mapped
// metadata key rather than indexing user.actors: an indexed select contributes
// no audit path, so a denial would record the agent it compared against but not
// the value that failed to match — the half an operator needs to debug it.
func TestBinding_AuditRecordsBothSides(t *testing.T) {
	bindingEnv(t)

	status, _ := h.UserLegRequestAs(t, leaderPort, h.UserLegUnboundRole, agentCert(t),
		map[string]string{"Authorization": "Bearer " + h.UserJWT(t)})
	if status == 200 {
		t.Fatal("expected the mismatch to be denied")
	}

	wantKeys := []string{"user.metadata." + h.UserLegActingAgentKey, "agent.principal"}
	nodeNum := h.NodeNumberForPort(leaderPort)

	var found bool
	for _, e := range h.ReadAuditEntries(t, nodeNum, h.UserLegMount) {
		if e.Auth == nil || e.Auth.PolicyResults == nil || e.Auth.PolicyResults.Condition == nil {
			continue
		}
		cond := e.Auth.PolicyResults.Condition
		if cond.Decision != "deny" || cond.Inputs == nil ||
			!strings.Contains(cond.Expression, h.UserLegActingAgentKey) {
			continue
		}
		found = true
		for _, k := range wantKeys {
			if _, ok := cond.Inputs[k]; !ok {
				t.Errorf("denial audit is missing input %q; recorded: %v", k, cond.Inputs)
			}
		}
		break
	}
	if !found {
		t.Error("no audited condition result carried the binding denial — the deciding inputs are unrecoverable")
	}
}
