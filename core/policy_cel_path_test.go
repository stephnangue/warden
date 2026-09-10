// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// TestCBP_PathCondition_EndToEnd parses a policy with a path-level CEL
// condition, compiles it into a CBP, and exercises allow/deny through
// AllowOperation. The condition reads request.data (body) and agent.metadata
// (from the TokenEntry threaded into AllowOperation).
func TestCBP_PathCondition_EndToEnd(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.ttl_seconds <= 3600 && agent.metadata.env == 'prod'"
		}
	`)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	prodTE := &logical.TokenEntry{Metadata: map[string]string{"env": "prod"}}

	req := func(ttl int) *logical.Request {
		return &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "db/issue-grant",
			Data:      map[string]any{"ttl_seconds": ttl},
		}
	}

	// Within cap and prod -> allow, with the condition decision recorded.
	res := cbp.AllowOperation(ctx, req(3600), prodTE, false)
	assert.True(t, res.Allowed)
	require.NotNil(t, res.Condition)
	assert.Equal(t, "allow", res.Condition.Decision)
	assert.Contains(t, res.Condition.Expression, "request.data.ttl_seconds")

	// Over cap -> deny, recorded.
	res = cbp.AllowOperation(ctx, req(7200), prodTE, false)
	assert.False(t, res.Allowed)
	require.NotNil(t, res.Condition)
	assert.Equal(t, "deny", res.Condition.Decision)

	// Wrong env -> deny (token metadata gate).
	devTE := &logical.TokenEntry{Metadata: map[string]string{"env": "dev"}}
	res = cbp.AllowOperation(ctx, req(100), devTE, false)
	assert.False(t, res.Allowed)
}

// TestCBP_PathCondition_RecordsInputs confirms a deciding path-level condition
// snapshots its referenced request/agent values into ConditionResult.Inputs
// (in clear — salting is an audit-layer opt-in).
func TestCBP_PathCondition_RecordsInputs(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.model == 'sonnet' && agent.metadata.env == 'prod'"
		}
	`)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	prodTE := &logical.TokenEntry{Metadata: map[string]string{"env": "prod"}}
	res := cbp.AllowOperation(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "db/issue-grant",
		Data:      map[string]any{"model": "opus"},
	}, prodTE, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.Condition)
	require.NotNil(t, res.Condition.Inputs)
	assert.Equal(t, "opus", res.Condition.Inputs["request.data.model"])
	assert.Equal(t, "prod", res.Condition.Inputs["agent.metadata.env"])
}

// TestCBP_PathCondition_MissingDataFailsClosed confirms a condition over an
// absent request.data key denies (fail-closed) and records a sanitized error
// category rather than a raw value.
func TestCBP_PathCondition_MissingDataFailsClosed(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.ttl_seconds <= 3600"
		}
	`)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// No Data at all -> request.data.ttl_seconds is a no-such-key error -> deny.
	res := cbp.AllowOperation(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "db/issue-grant",
	}, nil, false)
	assert.False(t, res.Allowed)
	require.NotNil(t, res.Condition)
	assert.Equal(t, "deny", res.Condition.Decision)
	assert.Equal(t, "no_such_key", res.Condition.ErrorKind)
}

// TestCBP_PathCondition_OptionalArgAllowsAbsent confirms the optional-syntax
// escape hatch: an absent key passes when the author opts in.
func TestCBP_PathCondition_OptionalArgAllowsAbsent(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.?ttl_seconds.orValue(0) <= 3600"
		}
	`)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	res := cbp.AllowOperation(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "db/issue-grant",
	}, nil, false)
	assert.True(t, res.Allowed)
}

// TestCBP_PathCondition_RejectedAtParse confirms invalid conditions fail at
// policy-write time with a directed error: a non-bool result and a path-level
// reference to the mcp-only call.* namespace.
func TestCBP_PathCondition_RejectedAtParse(t *testing.T) {
	for _, tc := range []struct{ name, cond string }{
		{"non-bool", `1 + 1`},
		{"call-in-path-level", `call.args.amount <= 1`},
		{"syntax", `request.data.x <=`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCBPPolicy(namespace.RootNamespace, `
				path "p" {
					capabilities = ["read"]
					condition = "`+tc.cond+`"
				}
			`)
			assert.Error(t, err)
		})
	}
}

// TestCBP_PathCondition_CapCheckOnlySkips confirms capability-listing does not
// evaluate the condition (returns early), so introspection stays request-free.
func TestCBP_PathCondition_CapCheckOnlySkips(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.ttl_seconds <= 3600"
		}
	`)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	res := cbp.AllowOperation(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "db/issue-grant",
	}, nil, true)
	// capCheckOnly returns the capability bitmap before the condition step;
	// the condition is not evaluated, so no decision is recorded.
	assert.Nil(t, res.Condition)
}

// TestCBP_PathCondition_MultiPolicyOR confirms two policies' CEL conditions on
// the same path OR across policies (more policies admit more requests).
func TestCBP_PathCondition_MultiPolicyOR(t *testing.T) {
	ctx := testContext()
	a := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "agent.metadata.team == 'red'" }`)
	b := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "agent.metadata.team == 'blue'" }`)
	cbp, err := NewCBP(ctx, []*Policy{a, b})
	require.NoError(t, err)

	read := &logical.Request{Operation: logical.ReadOperation, Path: "x"}
	team := func(v string) *logical.TokenEntry { return &logical.TokenEntry{Metadata: map[string]string{"team": v}} }

	assert.True(t, cbp.AllowOperation(ctx, read, team("red"), false).Allowed, "red satisfies policy A")
	assert.True(t, cbp.AllowOperation(ctx, read, team("blue"), false).Allowed, "blue satisfies policy B")
	assert.False(t, cbp.AllowOperation(ctx, read, team("green"), false).Allowed, "green satisfies neither")
}

// TestCBP_PathCondition_MergeUnionBuildsAllFields guards the activation-pruning
// union: two merged conditions read *different* namespace fields, so the shared
// activation must build the union (request.data AND agent.metadata). If it
// pruned to only the first condition's fields, the second would hit a missing
// key and fail closed — so "gold" (satisfying only policy B) proves both were
// built.
func TestCBP_PathCondition_MergeUnionBuildsAllFields(t *testing.T) {
	ctx := testContext()
	a := testParsePolicy(t, `path "kv/x" { capabilities = ["read"] condition = "agent.metadata.env == 'prod'" }`)
	b := testParsePolicy(t, `path "kv/x" { capabilities = ["read"] condition = "request.data.tier == 'gold'" }`)
	cbp, err := NewCBP(ctx, []*Policy{a, b})
	require.NoError(t, err)

	req := func(tier string) *logical.Request {
		return &logical.Request{Operation: logical.ReadOperation, Path: "kv/x", Data: map[string]any{"tier": tier}}
	}
	devTE := &logical.TokenEntry{Metadata: map[string]string{"env": "dev"}}

	// env=dev fails A; tier=gold satisfies B → allowed (B's request.data was built).
	assert.True(t, cbp.AllowOperation(ctx, req("gold"), devTE, false).Allowed)
	// env=dev fails A; tier=silver fails B → denied.
	assert.False(t, cbp.AllowOperation(ctx, req("silver"), devTE, false).Allowed)
}

// TestCBP_PathCondition_UnconditionalGrantWins confirms a policy that grants the
// path with no condition makes it unconditional (OR: an unconditional grant
// admits everything), overriding another policy's condition.
func TestCBP_PathCondition_UnconditionalGrantWins(t *testing.T) {
	ctx := testContext()
	a := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "agent.metadata.team == 'red'" }`)
	b := testParsePolicy(t, `path "x" { capabilities = ["read"] }`) // unconditional
	cbp, err := NewCBP(ctx, []*Policy{a, b})
	require.NoError(t, err)

	read := &logical.Request{Operation: logical.ReadOperation, Path: "x"}
	res := cbp.AllowOperation(ctx, read, &logical.TokenEntry{Metadata: map[string]string{"team": "green"}}, false)
	assert.True(t, res.Allowed, "unconditional grant from B admits any request")
}

// TestCBP_RequestParamsRemoved confirms the removed request-body parameter
// constraints are rejected at parse time with a directed "use CEL" error.
func TestCBP_RequestParamsRemoved(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"required", `required_parameters = ["owner"]`},
		{"allowed", `allowed_parameters = { tier = ["gold"] }`},
		{"denied", `denied_parameters = { internal = [] }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCBPPolicy(namespace.RootNamespace, `
				path "secret/data/app" {
					capabilities = ["create"]
					`+tc.body+`
				}
			`)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "have been removed")
			assert.Contains(t, err.Error(), "request.data")
		})
	}
}

// TestCBP_ConditionsBlockRemoved confirms the legacy conditions {} block is
// rejected at parse time with a directed "use CEL" error.
func TestCBP_ConditionsBlockRemoved(t *testing.T) {
	_, err := ParseCBPPolicy(namespace.RootNamespace, `
		path "secret/*" {
			capabilities = ["read"]
			conditions { token_metadata = ["env=prod"] }
		}
	`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conditions {} block has been removed")
	assert.Contains(t, err.Error(), "agent.metadata")
}

// TestCBP_RequestNamespace confirms request.namespace (the request's target
// namespace) is exposed and can be compared against agent.namespace (where the
// token was minted) — e.g. to deny a parent-namespace token acting in a child
// namespace. Both values are captured in the audited Inputs.
func TestCBP_RequestNamespace(t *testing.T) {
	env, err := baseCELEnv()
	require.NoError(t, err)
	src := "agent.namespace == request.namespace"
	cond, err := compileCELCondition(env, src)
	require.NoError(t, err)

	req := &logical.Request{Operation: logical.ReadOperation, Path: "x"}
	te := &logical.TokenEntry{NamespacePath: "team-a/"}
	now := time.Now()

	// Token minted in team-a/ acting in team-a/ -> allow.
	ok, res := evaluatePathConditions([]*compiledCondition{cond}, req, te, now, "team-a/")
	assert.True(t, ok)
	require.NotNil(t, res)
	assert.Equal(t, "allow", res.Decision)
	assert.Equal(t, "team-a/", res.Inputs["request.namespace"])
	assert.Equal(t, "team-a/", res.Inputs["agent.namespace"])

	// Same token acting in child namespace team-a/team-b/ -> deny.
	ok, res = evaluatePathConditions([]*compiledCondition{cond}, req, te, now, "team-a/team-b/")
	assert.False(t, ok)
	require.NotNil(t, res)
	assert.Equal(t, "deny", res.Decision)
	assert.Equal(t, "team-a/team-b/", res.Inputs["request.namespace"])
}

func BenchmarkAllowOperation_NoCondition(b *testing.B) {
	ctx := testContext()
	policy, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "db/issue-grant" { capabilities = ["create"] }
	`)
	cbp, _ := NewCBP(ctx, []*Policy{policy})
	req := &logical.Request{Operation: logical.CreateOperation, Path: "db/issue-grant"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

func BenchmarkAllowOperation_WithConditionRequestOnly(b *testing.B) {
	// Touches only the request namespace; the lazy activation never builds the
	// token namespace (metadata copy, policies/actors slices).
	ctx := testContext()
	policy, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.ttl_seconds <= 3600"
		}
	`)
	cbp, _ := NewCBP(ctx, []*Policy{policy})
	te := &logical.TokenEntry{Metadata: map[string]string{"env": "prod"}, Policies: []string{"p1", "p2"}}
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "db/issue-grant",
		Data:      map[string]any{"ttl_seconds": 3600},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, te, false)
	}
}

func BenchmarkAllowOperation_WithCondition(b *testing.B) {
	ctx := testContext()
	policy, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.ttl_seconds <= 3600 && agent.metadata.env == 'prod'"
		}
	`)
	cbp, _ := NewCBP(ctx, []*Policy{policy})
	te := &logical.TokenEntry{Metadata: map[string]string{"env": "prod"}, ExpireAt: time.Now().Add(time.Hour)}
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "db/issue-grant",
		Data:      map[string]any{"ttl_seconds": 3600},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, te, false)
	}
}

// TestCBP_PathCondition_RenamedFields drives the three token_-prefixed fields
// through the real pruned path: compile -> celAnalyzeRefs -> AgtFields ->
// lazy activation -> eval.
//
// This is the regression guard for the rename's sharpest edge. celAnalyzeRefs
// records the CEL field name ("token_type") and buildPrincipalNS gates on
// f.has("token_type"); if those two strings ever disagree, the field is pruned
// away, the expression hits a missing key, and every request denies. Because
// `agent` is a dyn map that is not a compile error — so only an end-to-end
// evaluation catches it. A unit test over buildPrincipalNS with all:true cannot:
// has() short-circuits on all and returns true for any string.
func TestCBP_PathCondition_RenamedFields(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "agent.token_type == 'cert_role' && agent.token_ttl_seconds <= 3600 && agent.token_expires_at > 0"
		}
	`)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	expireAt := time.Now().Add(30 * time.Minute)
	te := &logical.TokenEntry{Type: "cert_role", ExpireAt: expireAt}
	res := cbp.AllowOperation(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "db/issue-grant",
	}, te, false)

	assert.True(t, res.Allowed, "renamed fields must resolve through the pruned activation")
	require.NotNil(t, res.Condition)
	require.NotNil(t, res.Condition.Inputs)
	// The audit keys carry the new spelling — this is what a salt_fields entry
	// has to match.
	assert.Equal(t, "cert_role", res.Condition.Inputs["agent.token_type"])
	assert.Contains(t, res.Condition.Inputs, "agent.token_ttl_seconds")
	assert.Equal(t, strconv.FormatInt(expireAt.Unix(), 10), res.Condition.Inputs["agent.token_expires_at"])
	// The pre-rename spellings must not appear as audit keys.
	for _, k := range []string{"agent.type", "agent.ttl_seconds", "agent.expires_at"} {
		assert.NotContains(t, res.Condition.Inputs, k)
	}
}

// userReq builds a gateway-shaped request carrying a user principal.
func userReq(path string, userMeta map[string]string) *logical.Request {
	req := &logical.Request{Operation: logical.CreateOperation, Path: path}
	if userMeta != nil {
		req.User = &logical.UserPrincipal{
			TokenEntry: &logical.TokenEntry{
				PrincipalID: "user-8f21c3",
				RoleName:    "human",
				Metadata:    userMeta,
			},
			// A bearer secret. It must never reach an activation, which the
			// audit assertion below checks.
			RawToken: "eyJ.super.secret",
		}
	}
	return req
}

// TestCBP_UserAbsent covers the flag that turns a policy denial into a user
// challenge. Its whole job is to answer "might acquiring a user change this?",
// so the cases that must NOT set it matter as much as the ones that must.
func TestCBP_UserAbsent(t *testing.T) {
	ctx := testContext()
	agentTE := &logical.TokenEntry{
		PrincipalID: "agent-gateway",
		Metadata:    map[string]string{"team": "platform"},
	}

	denyWith := func(t *testing.T, condition string, req *logical.Request) *logical.ConditionResult {
		t.Helper()
		policy := testParsePolicy(t, `
			path "vault-gw/gateway" {
				capabilities = ["create"]
				condition = "`+condition+`"
			}
		`)
		cbp, err := NewCBP(ctx, []*Policy{policy})
		require.NoError(t, err)
		res := cbp.AllowOperation(ctx, req, agentTE, false)
		require.False(t, res.Allowed)
		require.NotNil(t, res.Condition)
		return res.Condition
	}

	noUser := func() *logical.Request {
		return &logical.Request{Operation: logical.CreateOperation, Path: "vault-gw/gateway"}
	}

	// The guarded shape: user.present short-circuits, so this is a clean false.
	t.Run("guarded condition, user absent", func(t *testing.T) {
		c := denyWith(t, "user.present && user.metadata.acting_agent == agent.principal", noUser())
		assert.True(t, c.UserAbsent)
		assert.Empty(t, c.ErrorKind, "the guard makes absence a decision, not an error")
	})

	// The unguarded shape takes the ERROR branch instead — user.metadata binds
	// to an empty map, so the access is a no_such_key. An implementation that
	// set the flag only where `deciding` is built on the false branch would give
	// this shape a bare 403 while the guarded one got a challenge.
	t.Run("unguarded condition, user absent", func(t *testing.T) {
		c := denyWith(t, "user.metadata.acting_agent == agent.principal", noUser())
		assert.True(t, c.UserAbsent, "the error branch must set the flag too")
		assert.Equal(t, "no_such_key", c.ErrorKind)
	})

	// A user IS present and simply does not match. Acquiring one cannot help —
	// they already have one.
	t.Run("user present but mismatched", func(t *testing.T) {
		req := noUser()
		req.User = &logical.UserPrincipal{
			TokenEntry: &logical.TokenEntry{Metadata: map[string]string{"acting_agent": "agent-other"}},
		}
		c := denyWith(t, "user.present && user.metadata.acting_agent == agent.principal", req)
		assert.False(t, c.UserAbsent)
	})

	// No condition reads the user, so a user is irrelevant to the outcome.
	t.Run("condition does not reference the user", func(t *testing.T) {
		c := denyWith(t, "agent.principal == 'someone-else'", noUser())
		assert.False(t, c.UserAbsent)
	})

	// Deny means every OR'd condition failed, so a user-referencing one anywhere
	// in the list is enough — even when an unrelated condition is the one
	// recorded as deciding.
	t.Run("mixed list, only one references the user", func(t *testing.T) {
		a := testParsePolicy(t, `path "vault-gw/gateway" { capabilities = ["create"] condition = "agent.principal == 'nobody'" }`)
		// `== true` because a condition must evaluate to bool and a dyn-map field
		// types as dyn; a bare `user.present` is rejected at write time.
		b := testParsePolicy(t, `path "vault-gw/gateway" { capabilities = ["create"] condition = "user.present == true" }`)
		cbp, err := NewCBP(ctx, []*Policy{a, b})
		require.NoError(t, err)
		res := cbp.AllowOperation(ctx, noUser(), agentTE, false)
		require.False(t, res.Allowed)
		require.NotNil(t, res.Condition)
		assert.True(t, res.Condition.UserAbsent)
	})

	// A capability denial returns before the condition gate, so there is no
	// ConditionResult at all and nothing can be converted to a challenge.
	t.Run("capability deny produces no condition result", func(t *testing.T) {
		policy := testParsePolicy(t, `path "vault-gw/gateway" { capabilities = ["read"] condition = "user.present == true" }`)
		cbp, err := NewCBP(ctx, []*Policy{policy})
		require.NoError(t, err)
		res := cbp.AllowOperation(ctx, noUser(), agentTE, false) // create, not read
		assert.False(t, res.Allowed)
		assert.Nil(t, res.Condition)
	})

	// The flag is a syntactic over-approximation: this condition can never pass
	// however good the user token is. It still draws the flag, so the client
	// makes one wasted round trip — but the retry arrives WITH a user, which
	// clears the flag and terminates at a 403. Pins that it cannot loop.
	t.Run("unsatisfiable user condition terminates", func(t *testing.T) {
		const cond = "user.present && agent.principal == 'alice'"
		first := denyWith(t, cond, noUser())
		assert.True(t, first.UserAbsent, "over-approximates: a user might have helped")

		withUser := noUser()
		withUser.User = &logical.UserPrincipal{TokenEntry: &logical.TokenEntry{}}
		second := denyWith(t, cond, withUser)
		assert.False(t, second.UserAbsent, "retry must not draw a second challenge")
	})
}

// TestCBP_UserCondition_ConsentBinding drives the agent-user binding end to end
// through the pruned activation: allow when the IdP's act.sub (mapped to the
// acting_agent metadata key) names this agent, deny when it names another.
//
// This is the round-trip guard for the user leg's pruning invariant, the same
// class of defect TestCBP_PathCondition_RenamedFields covers for the agent leg:
// if celAnalyzeRefs and buildPrincipalNS ever disagree on a key, the field is
// pruned away and every request denies, with no compile error to catch it.
func TestCBP_UserCondition_ConsentBinding(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "vault-gw/gateway" {
			capabilities = ["create"]
			condition = "user.present && user.metadata.acting_agent == agent.principal && user.metadata.team == agent.metadata.team"
		}
	`)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	agentTE := &logical.TokenEntry{
		PrincipalID: "agent-gateway",
		Metadata:    map[string]string{"team": "platform"},
	}

	t.Run("allows when act.sub names this agent", func(t *testing.T) {
		req := userReq("vault-gw/gateway", map[string]string{
			"acting_agent": "agent-gateway",
			"team":         "platform",
		})
		res := cbp.AllowOperation(ctx, req, agentTE, false)
		assert.True(t, res.Allowed)
	})

	t.Run("denies when act.sub names a different agent", func(t *testing.T) {
		req := userReq("vault-gw/gateway", map[string]string{
			"acting_agent": "agent-other",
			"team":         "platform",
		})
		res := cbp.AllowOperation(ctx, req, agentTE, false)
		assert.False(t, res.Allowed, "a user token minted for another agent must be denied")

		// Auditability is the reason this binding reads a mapped metadata key
		// rather than indexing user.actors: both sides of the comparison have
		// to land in the record, or the operator sees a denial without the
		// value that caused it.
		require.NotNil(t, res.Condition)
		require.NotNil(t, res.Condition.Inputs)
		assert.Equal(t, "agent-other", res.Condition.Inputs["user.metadata.acting_agent"])
		assert.Equal(t, "agent-gateway", res.Condition.Inputs["agent.principal"])
	})

	t.Run("denies when no user credential rode the request", func(t *testing.T) {
		res := cbp.AllowOperation(ctx, userReq("vault-gw/gateway", nil), agentTE, false)
		assert.False(t, res.Allowed, "user.present false must deny, not error")
		require.NotNil(t, res.Condition)
		assert.Empty(t, res.Condition.ErrorKind, "absence is a policy decision, not an eval error")
	})

	// evaluatePathConditions seeds its field-sets from the first condition and
	// unions the rest. With a single condition only the seed runs, so a dropped
	// union goes unnoticed until two policies name the same path — then the
	// second condition's user fields are pruned away and it denies on a missing
	// key. Cross-policy OR means the binding must still allow here.
	t.Run("unions user fields across two policies on one path", func(t *testing.T) {
		unrelated := testParsePolicy(t, `
			path "vault-gw/gateway" {
				capabilities = ["create"]
				condition = "agent.principal == 'nobody'"
			}
		`)
		merged, err := NewCBP(ctx, []*Policy{unrelated, policy})
		require.NoError(t, err)

		req := userReq("vault-gw/gateway", map[string]string{
			"acting_agent": "agent-gateway",
			"team":         "platform",
		})
		res := merged.AllowOperation(ctx, req, agentTE, false)
		assert.True(t, res.Allowed,
			"the second policy's user.* fields must survive the field-set union")
	})

	t.Run("denies when the acting_agent mapping is absent", func(t *testing.T) {
		// Dropping /act/sub from the role's metadata_claims removes the key, so
		// the binding fails closed rather than silently passing.
		req := userReq("vault-gw/gateway", map[string]string{"team": "platform"})
		res := cbp.AllowOperation(ctx, req, agentTE, false)
		assert.False(t, res.Allowed)
		require.NotNil(t, res.Condition)
		assert.Equal(t, "no_such_key", res.Condition.ErrorKind)
	})
}
