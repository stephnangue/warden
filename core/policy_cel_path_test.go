// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"strconv"
	"strings"
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
// same capability with no condition grants it unconditionally (OR: an
// unconditional grant admits everything), whatever another policy's condition
// says.
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

// teamEntry is a token whose metadata names its team.
func teamEntry(team string) *logical.TokenEntry {
	return &logical.TokenEntry{Metadata: map[string]string{"team": team}}
}

// TestCBP_PathCondition_BoundToItsStanza: a condition gates its own stanza's
// capabilities and no others, whichever policy comes first. An unconditional
// stanza for other capabilities on the same path does not lift it.
func TestCBP_PathCondition_BoundToItsStanza(t *testing.T) {
	ctx := testContext()
	gated := testParsePolicy(t, `path "aws/gateway*" {
		capabilities = ["delete"]
		condition    = "agent.metadata.team == 'red'"
	}`)
	open := testParsePolicy(t, `path "aws/gateway*" { capabilities = ["read", "create", "update", "patch"] }`)
	oneDocument := testParsePolicy(t, `
		path "aws/gateway*" {
			capabilities = ["delete"]
			condition    = "agent.metadata.team == 'red'"
		}
		path "aws/gateway*" {
			capabilities = ["read", "create", "update", "patch"]
		}
	`)

	for name, policies := range map[string][]*Policy{
		"gated first": {gated, open},
		"open first":  {open, gated},
		"one policy":  {oneDocument},
	} {
		t.Run(name, func(t *testing.T) {
			cbp, err := NewCBP(ctx, policies)
			require.NoError(t, err)
			op := func(o logical.Operation, team string) *CBPResults {
				return cbp.AllowOperation(ctx, &logical.Request{Operation: o, Path: "aws/gateway/bucket/key"}, teamEntry(team), false)
			}

			assert.True(t, op(logical.DeleteOperation, "red").Allowed)
			denied := op(logical.DeleteOperation, "green")
			assert.False(t, denied.Allowed, "the unconditional stanza brings no delete")
			require.NotNil(t, denied.Condition)
			assert.Equal(t, "deny", denied.Condition.Decision)

			read := op(logical.ReadOperation, "green")
			assert.True(t, read.Allowed)
			assert.Nil(t, read.Condition, "no condition gates a read")
		})
	}
}

// TestCBP_PathCondition_OnlyTheCapabilitysConditionsCount: of two conditional
// stanzas with different capabilities, each capability answers to its own.
func TestCBP_PathCondition_OnlyTheCapabilitysConditionsCount(t *testing.T) {
	ctx := testContext()
	const redOnly, blueOnly = "agent.metadata.team == 'red'", "agent.metadata.team == 'blue'"
	a := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "`+redOnly+`" }`)
	b := testParsePolicy(t, `path "x" { capabilities = ["delete"] condition = "`+blueOnly+`" }`)
	cbp, err := NewCBP(ctx, []*Policy{a, b})
	require.NoError(t, err)
	op := func(o logical.Operation, team string) *CBPResults {
		return cbp.AllowOperation(ctx, &logical.Request{Operation: o, Path: "x"}, teamEntry(team), false)
	}

	assert.True(t, op(logical.ReadOperation, "red").Allowed)
	assert.True(t, op(logical.DeleteOperation, "blue").Allowed)

	read := op(logical.ReadOperation, "blue")
	assert.False(t, read.Allowed, "delete's condition holding does not grant a read")
	require.NotNil(t, read.Condition)
	assert.Equal(t, redOnly, read.Condition.Expression, "the audit names read's condition")

	assert.False(t, op(logical.DeleteOperation, "red").Allowed)
}

// TestCBP_PathCondition_SudoBoundToItsStanza: sudo answers to the condition of
// the stanza bringing it, and that condition is evaluated only on a path that
// needs sudo.
func TestCBP_PathCondition_SudoBoundToItsStanza(t *testing.T) {
	ctx := testContext()
	c := createTestCore(t)
	const redOnly = "agent.metadata.team == 'red'"
	check := func(t *testing.T, cbp *CBP, team string, needSudo bool) *AuthzResults {
		t.Helper()
		return c.performPolicyChecks(ctx, cbp, teamEntry(team),
			&logical.Request{Operation: logical.ReadOperation, Path: "x"},
			&PolicyCheckOpts{RootPrivsRequired: needSudo})
	}

	t.Run("a stanza of its own", func(t *testing.T) {
		read := testParsePolicy(t, `path "x" { capabilities = ["read"] }`)
		sudo := testParsePolicy(t, `path "x" { capabilities = ["sudo"] condition = "`+redOnly+`" }`)
		cbp, err := NewCBP(ctx, []*Policy{read, sudo})
		require.NoError(t, err)

		held := check(t, cbp, "red", true)
		assert.True(t, held.Allowed)
		require.NotNil(t, held.CBPResults.Condition, "the condition that gave sudo is recorded")
		assert.Equal(t, "allow", held.CBPResults.Condition.Decision)
		assert.Equal(t, redOnly, held.CBPResults.Condition.Expression)

		refused := check(t, cbp, "green", true)
		assert.False(t, refused.Allowed, "unconditional read brings no sudo")
		require.NotNil(t, refused.CBPResults.Condition)
		assert.Equal(t, "deny", refused.CBPResults.Condition.Decision)
		assert.Equal(t, redOnly, refused.CBPResults.Condition.Expression)

		open := check(t, cbp, "green", false)
		assert.True(t, open.Allowed, "the path needs no sudo")
		assert.Nil(t, open.CBPResults.Condition, "sudo's condition is not evaluated, so the audit shows no deny")

		// A condition that ran and was discarded would show up as allocations.
		plain, err := NewCBP(ctx, []*Policy{read})
		require.NoError(t, err)
		req := &logical.Request{Operation: logical.ReadOperation, Path: "x"}
		te := teamEntry("green")
		allocs := func(cbp *CBP) float64 {
			return testing.AllocsPerRun(200, func() { cbp.allowOperation(ctx, req, te, false, false) })
		}
		assert.Equal(t, allocs(plain), allocs(cbp), "no CEL runs for a path that needs no sudo")

		assert.True(t, cbp.AllowOperation(ctx, req, te, true).RootPrivs, "a capability check reports the union")
		assert.Contains(t, cbp.Capabilities(ctx, "x"), SudoCapability)
	})

	t.Run("the operation's own stanza", func(t *testing.T) {
		recipe := testParsePolicy(t, `path "x" { capabilities = ["read", "sudo"] condition = "`+redOnly+`" }`)
		cbp, err := NewCBP(ctx, []*Policy{recipe})
		require.NoError(t, err)

		allowed := check(t, cbp, "red", true)
		assert.True(t, allowed.Allowed)
		assert.True(t, allowed.RootPrivs)
		assert.Equal(t, "allow", allowed.CBPResults.Condition.Decision)
		assert.False(t, check(t, cbp, "green", true).Allowed)
	})

	t.Run("an unconditional stanza brings it", func(t *testing.T) {
		gated := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "`+redOnly+`" }`)
		sudo := testParsePolicy(t, `path "x" { capabilities = ["sudo"] }`)
		cbp, err := NewCBP(ctx, []*Policy{gated, sudo})
		require.NoError(t, err)

		assert.True(t, check(t, cbp, "red", true).Allowed)
		assert.False(t, check(t, cbp, "green", true).Allowed, "read still answers to its condition")
	})
}

// TestCBP_PathCondition_BesideADeny: a deny at the same key refuses whatever a
// conditional stanza would grant, in either order.
func TestCBP_PathCondition_BesideADeny(t *testing.T) {
	ctx := testContext()
	gated := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "agent.metadata.team == 'red'" }`)
	deny := testParsePolicy(t, `path "x" { capabilities = ["deny"] }`)
	for name, policies := range map[string][]*Policy{"deny first": {deny, gated}, "deny last": {gated, deny}} {
		t.Run(name, func(t *testing.T) {
			cbp, err := NewCBP(ctx, policies)
			require.NoError(t, err)
			req := &logical.Request{Operation: logical.ReadOperation, Path: "x"}
			assert.False(t, cbp.AllowOperation(ctx, req, teamEntry("red"), false).Allowed)
		})
	}
}

// TestCBP_PathCondition_EmptyConditionsRefuse: an empty condition list reads as
// unconditional to the evaluator, so a gated capability with no condition to
// answer to is refused. NewCBP never builds such an entry.
func TestCBP_PathCondition_EmptyConditionsRefuse(t *testing.T) {
	ctx := testContext()
	cbp := &CBP{exactRules: map[string]*CBPPermissions{
		"x": {CapabilitiesBitmap: ReadCapabilityInt, ownerCaps: ReadCapabilityInt},
		"y": {CapabilitiesBitmap: ReadCapabilityInt | SudoCapabilityInt, ownerCaps: ReadCapabilityInt, unconditionalCaps: ReadCapabilityInt},
	}}
	read := func(path string) *CBPResults {
		return cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: path}, nil, false)
	}
	assert.False(t, read("x").Allowed)
	assert.False(t, read("y").RootPrivs)
}

// TestCBP_Deny_ConditionDecidesWhenItApplies: a conditional deny refuses when
// its condition holds and stands aside when it doesn't, in either policy order.
func TestCBP_Deny_ConditionDecidesWhenItApplies(t *testing.T) {
	ctx := testContext()
	const notRed = "agent.metadata.team != 'red'"
	grant := finalizedPolicy(t, "grant", PolicyTypeCBP, `path "x" { capabilities = ["read"] }`)
	guard := finalizedPolicy(t, "guard", PolicyTypeCBP, `path "x" { capabilities = ["deny"] condition = "`+notRed+`" }`)

	for name, policies := range map[string][]*Policy{"guard last": {grant, guard}, "guard first": {guard, grant}} {
		t.Run(name, func(t *testing.T) {
			cbp, err := NewCBP(ctx, policies)
			require.NoError(t, err)
			read := func(team string) *CBPResults {
				return cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "x"}, teamEntry(team), false)
			}

			refused := read("green")
			assert.False(t, refused.Allowed)
			assert.Equal(t, "guard", refused.DenyingPolicy)
			require.NotNil(t, refused.Condition)
			assert.Equal(t, "deny", refused.Condition.Decision)
			assert.Equal(t, notRed, refused.Condition.Expression)
			assert.Empty(t, refused.Condition.ErrorKind)

			allowed := read("red")
			assert.True(t, allowed.Allowed)
			assert.Empty(t, allowed.DenyingPolicy)
			assert.Nil(t, allowed.Condition, "a deny that stood aside records nothing")
		})
	}
}

// TestCBP_Deny_ReachesEveryMatchingPath: a deny is not ranked against grants,
// so specificity helps neither side.
func TestCBP_Deny_ReachesEveryMatchingPath(t *testing.T) {
	ctx := testContext()
	const notRed = "agent.metadata.team != 'red'"
	read := func(cbp *CBP, path, team string) bool {
		return cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: path}, teamEntry(team), false).Allowed
	}

	t.Run("a broader conditional deny beats a specific grant", func(t *testing.T) {
		cbp, err := NewCBP(ctx, []*Policy{
			testParsePolicy(t, `path "a/b/c" { capabilities = ["read"] }`),
			testParsePolicy(t, `path "a/*" { capabilities = ["deny"] condition = "`+notRed+`" }`),
		})
		require.NoError(t, err)
		assert.False(t, read(cbp, "a/b/c", "green"))
		assert.True(t, read(cbp, "a/b/c", "red"))
	})

	t.Run("a narrower conditional deny does not shadow a broad grant", func(t *testing.T) {
		cbp, err := NewCBP(ctx, []*Policy{
			testParsePolicy(t, `path "a/*" { capabilities = ["read"] }`),
			testParsePolicy(t, `path "a/b" { capabilities = ["deny"] condition = "`+notRed+`" }`),
		})
		require.NoError(t, err)
		assert.True(t, read(cbp, "a/b", "red"), "the rule stands aside and the broad grant decides")
		assert.False(t, read(cbp, "a/b", "green"))
		assert.True(t, read(cbp, "a/c", "green"), "the rule doesn't reach another path")
	})

	t.Run("a plain deny beats a specific grant from the same policy", func(t *testing.T) {
		cbp, err := NewCBP(ctx, []*Policy{testParsePolicy(t, `
			path "a/*" { capabilities = ["deny"] }
			path "a/public" { capabilities = ["read"] }
		`)})
		require.NoError(t, err)
		assert.False(t, read(cbp, "a/public", "red"))
	})

	t.Run("a plain deny beats a specific grant from another policy", func(t *testing.T) {
		cbp, err := NewCBP(ctx, []*Policy{
			testParsePolicy(t, `path "a/+/c" { capabilities = ["read"] }`),
			testParsePolicy(t, `path "a/*" { capabilities = ["deny"] }`),
		})
		require.NoError(t, err)
		assert.False(t, read(cbp, "a/b/c", "red"))
	})

	t.Run("a carve-out written into the deny works", func(t *testing.T) {
		cbp, err := NewCBP(ctx, []*Policy{testParsePolicy(t, `
			path "a/*" {
				capabilities = ["deny"]
				condition    = "request.path != 'a/public'"
			}
			path "a/*" { capabilities = ["read"] }
		`)})
		require.NoError(t, err)
		assert.True(t, read(cbp, "a/public", "green"))
		assert.False(t, read(cbp, "a/private", "green"))
	})
}

// TestCBP_Deny_MatchesTheFormsAGrantLookupTries covers every kind of pattern,
// and the trailing slash a List or Scan may be resolved without.
func TestCBP_Deny_MatchesTheFormsAGrantLookupTries(t *testing.T) {
	ctx := testContext()
	for _, tc := range []struct {
		name, pattern, path string
		op                  logical.Operation
		want                bool
	}{
		{"exact", "a/b", "a/b", logical.ReadOperation, true},
		{"exact, another path", "a/b", "a/c", logical.ReadOperation, false},
		{"exact, longer path", "a/b", "a/b/c", logical.ReadOperation, false},
		{"exact, list with a slash", "a/b", "a/b/", logical.ListOperation, true},
		{"exact, scan with a slash", "a/b", "a/b/", logical.ScanOperation, true},
		{"exact, read with a slash", "a/b", "a/b/", logical.ReadOperation, false},
		{"prefix", "a/*", "a/b/c", logical.ReadOperation, true},
		{"prefix, partial segment", "a/b*", "a/bcd", logical.ReadOperation, true},
		{"prefix, another path", "a/*", "b/c", logical.ReadOperation, false},
		{"wildcard", "a/+/c", "a/b/c", logical.ReadOperation, true},
		{"wildcard, too long", "a/+/c", "a/b/c/d", logical.ReadOperation, false},
		{"wildcard, too short", "a/+/c", "a/b", logical.ReadOperation, false},
		{"wildcard, another segment", "a/+/c", "a/b/d", logical.ReadOperation, false},
		{"wildcard, list with a slash", "a/+", "a/b/", logical.ListOperation, true},
		{"wildcard, read with a slash", "a/+", "a/b/", logical.ReadOperation, false},
		{"wildcard prefix", "a/+/c*", "a/b/cde/f", logical.ReadOperation, true},
		{"wildcard prefix, another segment", "a/+/c*", "a/b/d", logical.ReadOperation, false},
		{"wildcard first", "+/b", "a/b", logical.ReadOperation, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps := map[logical.Operation]string{logical.ReadOperation: "read", logical.ListOperation: "list", logical.ScanOperation: "scan"}[tc.op]
			cbp, err := NewCBP(ctx, []*Policy{
				testParsePolicy(t, `path "*" { capabilities = ["`+caps+`"] }`),
				testParsePolicy(t, `path "`+tc.pattern+`" { capabilities = ["deny"] }`),
			})
			require.NoError(t, err)
			res := cbp.AllowOperation(ctx, &logical.Request{Operation: tc.op, Path: tc.path}, nil, false)
			assert.Equal(t, tc.want, !res.Allowed)
		})
	}
}

// TestCBP_Deny_FailsClosed: a deny condition that errors fires. That includes
// reading a field an unread body doesn't have, which is why a has() guard, right
// on a grant, lets a caller escape a deny by relabelling the body.
func TestCBP_Deny_FailsClosed(t *testing.T) {
	ctx := testContext()
	grant := testParsePolicy(t, `path "x" { capabilities = ["create"] }`)
	create := func(t *testing.T, condition string) *CBPResults {
		t.Helper()
		guard := finalizedPolicy(t, "guard", PolicyTypeCBP, `path "x" { capabilities = ["deny"] condition = "`+condition+`" }`)
		cbp, err := NewCBP(ctx, []*Policy{grant, guard})
		require.NoError(t, err)
		return cbp.AllowOperation(ctx, &logical.Request{Operation: logical.CreateOperation, Path: "x"}, nil, false)
	}

	unguarded := create(t, "request.data.tier == 'gold'")
	assert.False(t, unguarded.Allowed)
	assert.Equal(t, "guard", unguarded.DenyingPolicy)
	require.NotNil(t, unguarded.Condition)
	assert.Equal(t, "no_such_key", unguarded.Condition.ErrorKind)

	assert.True(t, create(t, "has(request.data.tier) && request.data.tier == 'gold'").Allowed,
		"the guard makes an unread body false, so the rule doesn't fire")

	absent := create(t, "user.metadata.x == 'bad'")
	assert.False(t, absent.Allowed)
	require.NotNil(t, absent.Condition)
	assert.True(t, absent.Condition.UserAbsent, "a user could change the outcome")
}

// TestCBP_ConstantThatFailsKeepsItsPolicy: a condition whose constant fails to
// evaluate still loads, so its policy keeps working: a grant's `||` absorbs the
// error and a deny's error fires it.
func TestCBP_ConstantThatFailsKeepsItsPolicy(t *testing.T) {
	ctx := testContext()
	const bad = "request.path.matches('[')"
	grant := testParsePolicy(t, `
		path "x" { capabilities = ["read", "update"] condition = "`+bad+` || request.operation == 'read'" }
		path "y" { capabilities = ["read"] }
	`)
	guard := finalizedPolicy(t, "guard", PolicyTypeCBP, `path "y" { capabilities = ["deny"] condition = "`+bad+`" }`)
	cbp, err := NewCBP(ctx, []*Policy{grant, guard})
	require.NoError(t, err)
	allow := func(op logical.Operation, path string) *CBPResults {
		return cbp.AllowOperation(ctx, &logical.Request{Operation: op, Path: path}, nil, false)
	}

	assert.True(t, allow(logical.ReadOperation, "x").Allowed)
	assert.False(t, allow(logical.UpdateOperation, "x").Allowed)

	refused := allow(logical.ReadOperation, "y")
	assert.False(t, refused.Allowed)
	assert.Equal(t, "guard", refused.DenyingPolicy)
	require.NotNil(t, refused.Condition)
	assert.Equal(t, "eval_error", refused.Condition.ErrorKind)
}

// TestCBP_Deny_RecordsWhichPolicy: a plain deny names its policy on every way
// to a refusal and records no condition, since none ran.
func TestCBP_Deny_RecordsWhichPolicy(t *testing.T) {
	ctx := testContext()
	deny := finalizedPolicy(t, "closed", PolicyTypeCBP, `path "a/*" { capabilities = ["deny"] }`)
	read := finalizedPolicy(t, "reader", PolicyTypeCBP, `path "a/b" { capabilities = ["read"] }`)
	cbp, err := NewCBP(ctx, []*Policy{deny, read})
	require.NoError(t, err)

	for name, req := range map[string]*logical.Request{
		"no grant at the path": {Operation: logical.ReadOperation, Path: "a/none"},
		"grant lacks the op":   {Operation: logical.DeleteOperation, Path: "a/b"},
		"grant holds the op":   {Operation: logical.ReadOperation, Path: "a/b"},
	} {
		t.Run(name, func(t *testing.T) {
			res := cbp.AllowOperation(ctx, req, nil, false)
			assert.False(t, res.Allowed)
			assert.Equal(t, "closed", res.DenyingPolicy)
			assert.Nil(t, res.Condition)
		})
	}
}

// TestCBP_Deny_CapabilitiesReportIt: a capability check says deny under a plain
// deny at any depth. A conditional one is not evaluated there, as a conditional
// grant isn't.
func TestCBP_Deny_CapabilitiesReportIt(t *testing.T) {
	ctx := testContext()
	cbp, err := NewCBP(ctx, []*Policy{
		testParsePolicy(t, `path "broad/*" { capabilities = ["deny"] }`),
		testParsePolicy(t, `path "broad/specific" { capabilities = ["read"] }`),
		testParsePolicy(t, `path "open/*" { capabilities = ["read"] }`),
		testParsePolicy(t, `path "open/closed" { capabilities = ["deny"] }`),
		testParsePolicy(t, `path "open/maybe" { capabilities = ["deny"] condition = "false" }`),
	})
	require.NoError(t, err)

	assert.Equal(t, []string{DenyCapability}, cbp.Capabilities(ctx, "broad/specific"), "under a broader deny")
	assert.Equal(t, []string{DenyCapability}, cbp.Capabilities(ctx, "open/closed"), "a narrower deny over a broad grant")
	assert.Equal(t, []string{ReadCapability}, cbp.Capabilities(ctx, "open/maybe"))
}

// TestCBP_Deny_RootPrivsAndBypasses: a firing deny leaves no sudo behind, and
// root and Help answer to no deny, as they answer to no condition.
func TestCBP_Deny_RootPrivsAndBypasses(t *testing.T) {
	ctx := testContext()
	grant := testParsePolicy(t, `path "x" { capabilities = ["read", "sudo"] }`)
	deny := testParsePolicy(t, `path "x" { capabilities = ["deny"] condition = "true" }`)
	plain := testParsePolicy(t, `path "x" { capabilities = ["deny"] }`)
	read := &logical.Request{Operation: logical.ReadOperation, Path: "x"}

	cbp, err := NewCBP(ctx, []*Policy{grant, deny})
	require.NoError(t, err)
	res := cbp.AllowOperation(ctx, read, nil, false)
	assert.False(t, res.Allowed)
	assert.False(t, res.RootPrivs)

	help, err := NewCBP(ctx, []*Policy{plain})
	require.NoError(t, err)
	assert.True(t, help.AllowOperation(ctx, &logical.Request{Operation: logical.HelpOperation, Path: "x"}, nil, false).Allowed)

	root, err := NewCBP(ctx, []*Policy{plain})
	require.NoError(t, err)
	root.root = true
	assert.True(t, root.AllowOperation(ctx, read, nil, false).Allowed)
}

// TestCBP_Deny_ExpiredStanzaIsDropped: an expired deny stanza no longer applies.
func TestCBP_Deny_ExpiredStanzaIsDropped(t *testing.T) {
	ctx := testContext()
	deny := testParsePolicy(t, `path "x" { capabilities = ["deny"] expiration = "2099-01-01T00:00:00Z" }`)
	deny.Paths[0].Expiration = time.Now().Add(-time.Hour)
	grant := testParsePolicy(t, `path "x" { capabilities = ["read"] }`)
	cbp, err := NewCBP(ctx, []*Policy{deny, grant})
	require.NoError(t, err)
	assert.True(t, cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "x"}, nil, false).Allowed)
}

// TestCBP_Deny_InvalidConditionIsRefused: a deny's condition is compiled, so a
// broken one is refused where it used to be ignored.
func TestCBP_Deny_InvalidConditionIsRefused(t *testing.T) {
	_, err := ParseCBPPolicy(namespace.RootNamespace, `path "x" { capabilities = ["deny"] condition = "request.client_ip ==" }`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "condition")
}

// TestCBP_Deny_NoAllocationToMatch: scanning deny rules that don't apply,
// segment wildcards included, costs a request no allocation.
func TestCBP_Deny_NoAllocationToMatch(t *testing.T) {
	ctx := testContext()
	grant := testParsePolicy(t, `path "kv/*" { capabilities = ["read"] }`)
	withRules, err := NewCBP(ctx, []*Policy{grant, testParsePolicy(t, `
		path "other/x" { capabilities = ["deny"] }
		path "other/*" { capabilities = ["deny"] }
		path "kv/+/secret" { capabilities = ["deny"] }
		path "other/maybe" { capabilities = ["deny"] condition = "true" }
	`)})
	require.NoError(t, err)
	without, err := NewCBP(ctx, []*Policy{grant})
	require.NoError(t, err)

	req := &logical.Request{Operation: logical.ReadOperation, Path: "kv/app/config"}
	allocs := func(cbp *CBP) float64 {
		return testing.AllocsPerRun(200, func() { cbp.AllowOperation(ctx, req, nil, false) })
	}
	assert.Equal(t, allocs(without), allocs(withRules))
}

// TestCBP_Deny_InANamespace: a rule's path carries its policy's namespace and
// the request's path its own, through different code, and they must meet.
func TestCBP_Deny_InANamespace(t *testing.T) {
	ns := &namespace.Namespace{ID: "ns1", Path: "ns1/"}
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	policy, err := ParseCBPPolicy(ns, `
		path "a/*" { capabilities = ["read"] }
		path "a/+/secret" { capabilities = ["deny"] }
		path "a/guarded" { capabilities = ["deny"] condition = "true" }
	`)
	require.NoError(t, err)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)
	read := func(path string) bool {
		return cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: path}, nil, false).Allowed
	}

	assert.False(t, read("a/x/secret"))
	assert.False(t, read("a/guarded"))
	assert.True(t, read("a/x/open"))
}

// TestCBP_Deny_ConditionalOnAListPath: a conditional deny is asked on the form
// without the trailing slash too.
func TestCBP_Deny_ConditionalOnAListPath(t *testing.T) {
	ctx := testContext()
	cbp, err := NewCBP(ctx, []*Policy{
		testParsePolicy(t, `path "*" { capabilities = ["list"] }`),
		testParsePolicy(t, `path "a/+" { capabilities = ["deny"] condition = "true" }`),
	})
	require.NoError(t, err)
	assert.False(t, cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ListOperation, Path: "a/b/"}, nil, false).Allowed)
}

// TestCBP_Deny_SegmentsMissing: a wildcard deny built without the parser's
// split still matches, so it can't silently stop applying.
func TestCBP_Deny_SegmentsMissing(t *testing.T) {
	r := denyRule{stanza: &PathRules{Path: "a/+/c*", HasSegmentWildcards: true}}
	assert.True(t, r.matches("a/b/cd"))
	assert.False(t, r.matches("a/b/d"))
}

// TestMatchSegments pins the comparison the grant ranking and the deny rules
// share.
func TestMatchSegments(t *testing.T) {
	for _, tc := range []struct {
		pattern   []string
		isPrefix  bool
		path      string
		wildcards int
		ok        bool
	}{
		{[]string{"a", "+", "c"}, false, "a/b/c", 1, true},
		{[]string{"a", "+", "c"}, false, "a/b/c/", 0, false},
		{[]string{"a", "+", "c"}, false, "a/b", 0, false},
		{[]string{"+", "+"}, false, "a/b", 2, true},
		{[]string{"a", "+"}, false, "a/", 1, true},
		{[]string{"a", "+", "c"}, true, "a/b/cd/e", 1, true},
		{[]string{"a", "+", ""}, true, "a/b/", 1, true},
		{[]string{"a", "+", ""}, true, "a/b/c/d", 1, true},
		{[]string{"a", "+", ""}, true, "a/b", 0, false},
		{[]string{"a", "+", "c"}, true, "a/b/d", 0, false},
		{[]string{"+"}, false, "a", 1, true},
		{[]string{"+"}, false, "a/b", 0, false},
		{[]string{"+", "b"}, true, "a/bc/d", 1, true},
	} {
		wildcards, ok := matchSegments(tc.pattern, tc.isPrefix, tc.path)
		assert.Equal(t, tc.ok, ok, "%v %s", tc.pattern, tc.path)
		assert.Equal(t, tc.wildcards, wildcards, "%v %s", tc.pattern, tc.path)
	}
}

// TestCBP_FailedGrantNamesNoDenyingPolicy: a grant whose condition failed
// denied nothing, so only a deny stanza is ever named.
func TestCBP_FailedGrantNamesNoDenyingPolicy(t *testing.T) {
	ctx := testContext()
	red := finalizedPolicy(t, "red-read", PolicyTypeCBP, `path "x" { capabilities = ["read"] condition = "agent.metadata.team == 'red'" }`)
	cbp, err := NewCBP(ctx, []*Policy{red})
	require.NoError(t, err)

	refused := cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "x"}, teamEntry("green"), false)
	assert.False(t, refused.Allowed)
	require.NotNil(t, refused.Condition)
	assert.Empty(t, refused.DenyingPolicy)
}

// TestCBP_GrantingPolicies_OnlyWhatGranted: the audit names the stanzas that
// granted this request, not every stanza that could have.
func TestCBP_GrantingPolicies_OnlyWhatGranted(t *testing.T) {
	ctx := testContext()
	red := finalizedPolicy(t, "red", PolicyTypeCBP, `path "x" { capabilities = ["read"] condition = "agent.metadata.team == 'red'" }`)
	blue := finalizedPolicy(t, "blue", PolicyTypeCBP, `path "x" { capabilities = ["read"] condition = "agent.metadata.team == 'blue'" }`)
	open := finalizedPolicy(t, "open", PolicyTypeCBP, `path "x" { capabilities = ["read"] }`)
	granting := func(cbp *CBP, team string) []string {
		res := cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "x"}, teamEntry(team), false)
		require.True(t, res.Allowed)
		names := make([]string, 0, len(res.GrantingPolicies))
		for _, p := range res.GrantingPolicies {
			names = append(names, p.Name)
		}
		return names
	}

	conditional, err := NewCBP(ctx, []*Policy{red, blue})
	require.NoError(t, err)
	assert.Equal(t, []string{"red"}, granting(conditional, "red"))
	assert.Equal(t, []string{"blue"}, granting(conditional, "blue"))

	mixed, err := NewCBP(ctx, []*Policy{red, open})
	require.NoError(t, err)
	assert.Equal(t, []string{"open"}, granting(mixed, "red"), "an unconditional stanza decides, with no condition run")
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
	ok, res, _ := evaluatePathConditions([]*compiledCondition{cond}, req, te, now, "team-a/")
	assert.True(t, ok)
	require.NotNil(t, res)
	assert.Equal(t, "allow", res.Decision)
	assert.Equal(t, "team-a/", res.Inputs["request.namespace"])
	assert.Equal(t, "team-a/", res.Inputs["agent.namespace"])

	// Same token acting in child namespace team-a/team-b/ -> deny.
	ok, res, _ = evaluatePathConditions([]*compiledCondition{cond}, req, te, now, "team-a/team-b/")
	assert.False(t, ok)
	require.NotNil(t, res)
	assert.Equal(t, "deny", res.Decision)
	assert.Equal(t, "team-a/team-b/", res.Inputs["request.namespace"])
}

// A request string is boxed once per evaluation, and a condition's source is
// stripped for audit once, at compile: a multi-line condition reading
// request.path on every clause allocates what a one-line condition reading it
// once does, and audits the same input.
func TestCBP_RequestFieldBoxedOnce(t *testing.T) {
	env, err := baseCELEnv()
	require.NoError(t, err)
	once, err := compileCELCondition(env, `request.path.startsWith("sys/x/")`)
	require.NoError(t, err)
	many, err := compileCELCondition(env, `request.path == "sys/a" || request.path == "sys/b" ||
request.path.startsWith("sys/c/") || request.path.startsWith("sys/d/") ||
request.path.startsWith("sys/x/")`)
	require.NoError(t, err)

	req := &logical.Request{Operation: logical.ReadOperation, Path: "sys/x/y"}
	now := time.Now()
	for _, cond := range []*compiledCondition{once, many} {
		ok, res, _ := evaluatePathConditions([]*compiledCondition{cond}, req, nil, now, "")
		require.True(t, ok)
		assert.Equal(t, "sys/x/y", res.Inputs["request.path"])
	}
	allocs := func(cond *compiledCondition) float64 {
		return testing.AllocsPerRun(200, func() {
			evaluatePathConditions([]*compiledCondition{cond}, req, nil, now, "")
		})
	}
	assert.Equal(t, allocs(once), allocs(many))
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

// BenchmarkAllowOperation_MergedConditions is an entry merged from two policies
// whose conditions both grant the operation: the gate ORs them over one
// activation built for the union of what they read.
func BenchmarkAllowOperation_MergedConditions(b *testing.B) {
	ctx := testContext()
	first, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "db/issue-grant" { capabilities = ["create"] condition = "agent.metadata.env == 'dev'" }
	`)
	second, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "db/issue-grant" { capabilities = ["create"] condition = "request.data.ttl_seconds <= 3600" }
	`)
	cbp, _ := NewCBP(ctx, []*Policy{first, second})
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

// BenchmarkAllowOperation_UnconditionalBesideConditional is an entry where an
// unconditional stanza grants the operation and another stanza's condition
// gates a different capability: nothing is evaluated.
func BenchmarkAllowOperation_UnconditionalBesideConditional(b *testing.B) {
	ctx := testContext()
	open, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "db/issue-grant" { capabilities = ["create"] }
	`)
	gated, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "db/issue-grant" { capabilities = ["delete"] condition = "agent.metadata.env == 'prod'" }
	`)
	cbp, _ := NewCBP(ctx, []*Policy{gated, open})
	req := &logical.Request{Operation: logical.CreateOperation, Path: "db/issue-grant"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

// BenchmarkAllowOperation_PlainDenies is a request that several plain deny
// rules, segment wildcards included, are checked against and none apply to.
func BenchmarkAllowOperation_PlainDenies(b *testing.B) {
	ctx := testContext()
	grant, _ := ParseCBPPolicy(namespace.RootNamespace, `path "kv/*" { capabilities = ["read"] }`)
	denies, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "other/x" { capabilities = ["deny"] }
		path "other/*" { capabilities = ["deny"] }
		path "kv/+/secret" { capabilities = ["deny"] }
	`)
	cbp, _ := NewCBP(ctx, []*Policy{grant, denies})
	req := &logical.Request{Operation: logical.ReadOperation, Path: "kv/app/config"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

// BenchmarkAllowOperation_SizeDependentCondition is a condition whose cost grows
// with the request body, so it runs under the runtime cost limit.
func BenchmarkAllowOperation_SizeDependentCondition(b *testing.B) {
	ctx := testContext()
	policy, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.all(k, k != '')"
		}
	`)
	cbp, _ := NewCBP(ctx, []*Policy{policy})
	data := make(map[string]any, 8)
	for i := range 8 {
		data["k"+strconv.Itoa(i)] = i
	}
	req := &logical.Request{Operation: logical.CreateOperation, Path: "db/issue-grant", Data: data}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

// BenchmarkAllowOperation_PathInList is warden-viewer's exact paths as one `in`,
// a set lookup, against the chain of `==` it replaced, on the last path.
func BenchmarkAllowOperation_PathInList(b *testing.B) {
	paths := []string{
		"sys/providers", "sys/skills", "sys/roles", "sys/auth", "sys/audit",
		"sys/namespaces", "sys/oidc-issuer/config", "sys/protected-resource/config",
	}
	eq := make([]string, len(paths))
	quoted := make([]string, len(paths))
	for i, p := range paths {
		eq[i] = "request.path == '" + p + "'"
		quoted[i] = "'" + p + "'"
	}
	for _, bc := range []struct{ name, condition string }{
		{"eq_chain", strings.Join(eq, " || ")},
		{"in_list", "request.path in [" + strings.Join(quoted, ", ") + "]"},
	} {
		b.Run(bc.name, func(b *testing.B) {
			ctx := testContext()
			policy, _ := ParseCBPPolicy(namespace.RootNamespace, `path "*" { capabilities = ["read"] condition = "`+bc.condition+`" }`)
			cbp, _ := NewCBP(ctx, []*Policy{policy})
			req := &logical.Request{Operation: logical.ReadOperation, Path: paths[len(paths)-1]}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = cbp.AllowOperation(ctx, req, nil, false)
			}
		})
	}
}

// BenchmarkAllowOperation_ConstantRegex is a condition matching a constant
// pattern, compiled once with the program.
func BenchmarkAllowOperation_ConstantRegex(b *testing.B) {
	ctx := testContext()
	policy, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "kv/*" { capabilities = ["read"] condition = "request.path.matches('^kv/(app|web)/[a-z]+$')" }
	`)
	cbp, _ := NewCBP(ctx, []*Policy{policy})
	req := &logical.Request{Operation: logical.ReadOperation, Path: "kv/app/config"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, nil, false)
	}
}

// BenchmarkAllowOperation_ConditionalDeny is a conditional deny that matches
// the path and stands aside, the cost a guarded request pays.
func BenchmarkAllowOperation_ConditionalDeny(b *testing.B) {
	ctx := testContext()
	grant, _ := ParseCBPPolicy(namespace.RootNamespace, `path "kv/*" { capabilities = ["read"] }`)
	guard, _ := ParseCBPPolicy(namespace.RootNamespace, `
		path "kv/*" { capabilities = ["deny"] condition = "agent.metadata.env != 'prod'" }
	`)
	cbp, _ := NewCBP(ctx, []*Policy{grant, guard})
	te := &logical.TokenEntry{Metadata: map[string]string{"env": "prod"}, ExpireAt: time.Now().Add(time.Hour)}
	req := &logical.Request{Operation: logical.ReadOperation, Path: "kv/app/config"}
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
			condition = "agent.token_type == 'identity_token' && agent.token_ttl_seconds <= 3600 && agent.token_expires_at > 0"
		}
	`)
	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	expireAt := time.Now().Add(30 * time.Minute)
	te := &logical.TokenEntry{Type: "identity_token", ExpireAt: expireAt}
	res := cbp.AllowOperation(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "db/issue-grant",
	}, te, false)

	assert.True(t, res.Allowed, "renamed fields must resolve through the pruned activation")
	require.NotNil(t, res.Condition)
	require.NotNil(t, res.Condition.Inputs)
	// The audit keys carry the new spelling — this is what a salt_fields entry
	// has to match.
	assert.Equal(t, "identity_token", res.Condition.Inputs["agent.token_type"])
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
