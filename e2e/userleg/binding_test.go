//go:build e2e

package userleg

import (
	"strings"
	"testing"

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

// TestBinding_MissingUserDenied covers `user.present`. A user credential is
// optional on a protected-resource mount, so its absence has to be a decision
// the condition makes — not an error, and not a silent allow.
//
// Uses the same certificate that succeeds in TestBinding_MatchingAgentAllowed,
// so the only difference is the missing Authorization header.
func TestBinding_MissingUserDenied(t *testing.T) {
	actingAgent := bindingEnv(t)

	cert, _ := h.GenerateClientCert(t, agentCAPEM, agentCAKey, actingAgent)
	status, body := h.UserLegRequestAs(t, leaderPort, h.UserLegBoundRole, cert, nil)

	if status == 200 {
		t.Fatalf("a bound path must not be reachable without a user credential, got 200: %s", string(body))
	}
	if status != 403 {
		t.Errorf("absence of a user is a policy denial, not an error; got %d: %s", status, string(body))
	}
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
