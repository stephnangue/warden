//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The rows here are provider-independent: they check the chain itself rather
// than any one extractor. Where a single carrier is needed they use openai for
// the plain cases and newrelic where the assertion depends on the credential
// landing somewhere other than Authorization. Per-provider behaviour lives in
// the file named for that provider.

// injection is what a provider's credential extractor must have produced.
type injection struct {
	env  h.ProviderEnv
	want map[string]string
}

// injections pins one positive credential-extractor branch per provider. The
// header names differ by provider by design: that difference is most of what the
// credential extractors do.
var injections = []injection{
	{openaiEnv, map[string]string{"Authorization": "Bearer " + openaiKey}},
	{anthropicEnv, map[string]string{"x-api-key": anthropicKey}},
	{newrelicEnv, map[string]string{"Api-Key": newrelicKey}},
	{elasticEnv, map[string]string{"Authorization": "ApiKey " + elasticKey}},
}

// TestFullChain_CertAgentWithUser is the reference shape the suite exists for:
// the agent arrives out of band as a certificate, leaving Authorization free to
// carry a user. Both principals resolve, the minted credential goes upstream,
// and neither inbound credential does.
func TestFullChain_CertAgentWithUser(t *testing.T) {
	ensureEnv(t)

	for _, tc := range injections {
		t.Run(tc.env.Mount, func(t *testing.T) {
			upstream.Reset()

			status, body, _ := h.ChainRequest(t, leaderPort, tc.env, h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Bearer:       h.FullChainUserJWT(t),
				Role:         tc.env.CertRole(),
				// Sent so the AlwaysAbsent entries for them are load-bearing: a
				// header the request never carried is trivially absent upstream,
				// and would stay absent however broken the strip list became.
				Headers: h.InertDecoyHeaders(),
			})

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      tc.want,
				Absent:        h.AlwaysAbsent(),
				UpstreamCalls: 1,
			})
		})
	}
}

// TestFullChain_UserIsAttributedInAudit proves the Bearer credential was
// captured as a user principal rather than silently ignored. Without this, a
// provider that dropped the user entirely would still pass every header
// assertion above.
func TestFullChain_UserIsAttributedInAudit(t *testing.T) {
	ensureEnv(t)

	probe := h.ProbePath("audit-user")
	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         openaiEnv.CertRole(),
		Path:         probe,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + openaiKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}

// TestFullChain_AgentOnlyCapturesNoUser is the counterpart: with no
// Authorization at all the request still succeeds, and must not acquire a user
// principal from anywhere. An agent-only request that picked one up would
// attribute actions to someone who never made them.
func TestFullChain_AgentOnlyCapturesNoUser(t *testing.T) {
	ensureEnv(t)

	probe := h.ProbePath("audit-agent-only")
	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Role:         openaiEnv.CertRole(),
		Path:         probe,
	})
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + openaiKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	h.AssertAuditUser(t, leaderPort, probe, "")
}

// TestFullChain_AgentTokenHeaderWithUser covers the dedicated agent channel. It
// exists so an agent that cannot present a certificate still leaves
// Authorization free for the user, and it deliberately outranks a certificate —
// a sidecar makes a certificate present on nearly every request, so letting the
// certificate win would make the explicit channel unusable.
//
// The certificate is sent precisely because it must lose. The mount's agent leg
// is bearer-only here, so if the certificate were consulted first the extractor
// would yield an empty agent and the certificate login would fail against a JWT
// mount — the 200 below is what pins the ordering. Without the certificate the
// test would show only that the channel works in isolation.
func TestFullChain_AgentTokenHeaderWithUser(t *testing.T) {
	ensureEnv(t)
	useJWTAgentLeg(t, openaiEnv)

	probe := h.ProbePath("agent-token-header")
	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		AgentToken:   h.GetDefaultJWT(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         openaiEnv.JWTAgentRole(),
		Path:         probe,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + openaiKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
	h.AssertAuditUser(t, leaderPort, probe, h.FullChainUserSubject)
}

// TestFullChain_AuthorizationNeverReachesUpstream checks that a user credential
// never proxies onward, with and without a user present.
//
// It covers the guarantee, not both implementations of it. Two layers remove the
// header — core deletes it once a user is captured, and this provider's strip
// list removes it unconditionally — and the second masks the first: deleting
// core's Del would not fail either subtest, because the strip list still catches
// it. Core's layer is only observable where no strip list applies (streaming and
// git paths), and is pinned at unit level in core/request_handler_user_test.go.
// Do not read a pass here as covering it.
//
// newrelic is the carrier because it injects into Api-Key, leaving Authorization
// untouched by the credential extractor — so whatever arrives there arrived by
// leak rather than by injection overwriting the evidence.
func TestFullChain_AuthorizationNeverReachesUpstream(t *testing.T) {
	ensureEnv(t)

	cases := []struct {
		name     string
		withUser bool
	}{
		{"user captured", true},
		{"no user", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream.Reset()

			opts := h.ChainOpts{
				AgentCertPEM: agentCert(t),
				Role:         newrelicEnv.CertRole(),
			}
			if tc.withUser {
				opts.Bearer = h.FullChainUserJWT(t)
			}

			status, body, _ := h.ChainRequest(t, leaderPort, newrelicEnv, opts)

			h.AssertChain(t, upstream, status, body, h.ChainWant{
				Status:        200,
				Injected:      map[string]string{"Api-Key": newrelicKey},
				Absent:        h.AlwaysAbsent("Authorization"),
				UpstreamCalls: 1,
			})
		})
	}
}

// TestFullChain_OperatorTokenPlusUserIsRejected pins the gate that fires before
// any token extractor runs. The operator credential carries no user principal,
// so combining it with an Authorization credential on a mount that expects one
// is ambiguous rather than merely unusual — and it is refused as a request
// error, not silently resolved one way.
func TestFullChain_OperatorTokenPlusUserIsRejected(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		WardenToken: h.RootToken(t),
		Bearer:      h.FullChainUserJWT(t),
		Role:        openaiEnv.CertRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        400,
		UpstreamCalls: 0,
	})
	// The message must name the way out, or the caller has a rejection with no
	// remedy.
	if !strings.Contains(string(body), "X-Warden-Agent-Token") {
		t.Errorf("rejection should name X-Warden-Agent-Token as the fix, got: %s", body)
	}
}

// TestFullChain_NonOptedInMountIsUnaffected is the control for the test above.
// The same header combination on a mount without a user leg must not be
// rejected as ambiguous: there is no second principal to be ambiguous about, and
// the pre-existing single-principal behaviour has to survive the feature. Without
// this, a 400 raised for some unrelated reason would look like the gate working.
func TestFullChain_NonOptedInMountIsUnaffected(t *testing.T) {
	ensureEnv(t)

	h.SetFullChainLegs(t, leaderPort, upstream.URL, anthropicEnv, h.CertAgentPath, "")
	t.Cleanup(func() { h.ResetFullChainLegs(t, leaderPort, upstream.URL, anthropicEnv) })

	status, body, _ := h.ChainRequest(t, leaderPort, anthropicEnv, h.ChainOpts{
		WardenToken: h.RootToken(t),
		Bearer:      h.FullChainUserJWT(t),
		Role:        anthropicEnv.CertRole(),
	})

	// The request still fails, but further along and for an unrelated reason: an
	// operator token binds no credential spec, so there is nothing to mint.
	//
	// That failure is also a 400 — the same status the ambiguity gate returns —
	// so the status alone cannot tell the two apart and the body has to. Both
	// halves are needed: the positive check proves the request reached the mint,
	// which it could only do by passing the gate, and the negative check proves
	// the gate did not fire on the way. Asserting only the negative would let
	// anything that failed earlier pass as if the gate had stayed quiet.
	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        400,
		UpstreamCalls: 0,
	})
	if !strings.Contains(string(body), "credential spec") {
		t.Errorf("request did not reach the mint, so it proves nothing about the gate: %s", body)
	}
	if strings.Contains(string(body), "X-Warden-Agent-Token") {
		t.Errorf("mount without a user leg raised the ambiguity error: %s", body)
	}
}

// TestFullChain_PolicyDenialStopsBeforeUpstream checks that authorization is
// decided before forwarding. The role authenticates and mints exactly as the
// allowed one does; only its policy differs — so a request that reached the
// upstream anyway would have leaked the credential on a denied call.
func TestFullChain_PolicyDenialStopsBeforeUpstream(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         openaiEnv.DenyRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})
}

// TestFullChain_UntrustedAgentCertIsRejected mints a well-formed certificate
// from a CA the auth mount does not trust. It fails as an agent, and nothing is
// forwarded.
func TestFullChain_UntrustedAgentCertIsRejected(t *testing.T) {
	ensureEnv(t)

	otherCAPEM, otherCAKey := h.GenerateTestCA(t)
	rogueCert, _ := h.GenerateClientCert(t, otherCAPEM, otherCAKey, h.FullChainAgentCN)

	status, body, _ := h.ChainRequest(t, leaderPort, openaiEnv, h.ChainOpts{
		AgentCertPEM: rogueCert,
		Bearer:       h.FullChainUserJWT(t),
		Role:         openaiEnv.CertRole(),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        401,
		UpstreamCalls: 0,
	})
}
