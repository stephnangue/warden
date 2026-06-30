// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// TestCBP_PathCondition_EndToEnd parses a policy with a path-level CEL
// condition, compiles it into a CBP, and exercises allow/deny through
// AllowOperation. The condition reads request.data (body) and token.metadata
// (from the TokenEntry threaded into AllowOperation).
func TestCBP_PathCondition_EndToEnd(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "db/issue-grant" {
			capabilities = ["create"]
			condition = "request.data.ttl_seconds <= 3600 && token.metadata.env == 'prod'"
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
	a := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "token.metadata.team == 'red'" }`)
	b := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "token.metadata.team == 'blue'" }`)
	cbp, err := NewCBP(ctx, []*Policy{a, b})
	require.NoError(t, err)

	read := &logical.Request{Operation: logical.ReadOperation, Path: "x"}
	team := func(v string) *logical.TokenEntry { return &logical.TokenEntry{Metadata: map[string]string{"team": v}} }

	assert.True(t, cbp.AllowOperation(ctx, read, team("red"), false).Allowed, "red satisfies policy A")
	assert.True(t, cbp.AllowOperation(ctx, read, team("blue"), false).Allowed, "blue satisfies policy B")
	assert.False(t, cbp.AllowOperation(ctx, read, team("green"), false).Allowed, "green satisfies neither")
}

// TestCBP_PathCondition_UnconditionalGrantWins confirms a policy that grants the
// path with no condition makes it unconditional (OR: an unconditional grant
// admits everything), overriding another policy's condition.
func TestCBP_PathCondition_UnconditionalGrantWins(t *testing.T) {
	ctx := testContext()
	a := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "token.metadata.team == 'red'" }`)
	b := testParsePolicy(t, `path "x" { capabilities = ["read"] }`) // unconditional
	cbp, err := NewCBP(ctx, []*Policy{a, b})
	require.NoError(t, err)

	read := &logical.Request{Operation: logical.ReadOperation, Path: "x"}
	res := cbp.AllowOperation(ctx, read, &logical.TokenEntry{Metadata: map[string]string{"team": "green"}}, false)
	assert.True(t, res.Allowed, "unconditional grant from B admits any request")
}

// TestCBP_PathCondition_MixedMechanismsNotFailOpen is the regression guard for
// the merge fail-open: a CEL-only policy and a conditions{}-only policy on one
// path must NOT collapse to unconditional. A request satisfying neither is
// denied.
func TestCBP_PathCondition_MixedMechanismsNotFailOpen(t *testing.T) {
	ctx := testContext()
	celOnly := testParsePolicy(t, `path "x" { capabilities = ["read"] condition = "token.metadata.env == 'prod'" }`)
	structuredOnly := testParsePolicy(t, `path "x" { capabilities = ["read"] conditions { token_metadata = ["team=red"] } }`)
	cbp, err := NewCBP(ctx, []*Policy{celOnly, structuredOnly})
	require.NoError(t, err)

	// Satisfies neither gate -> must be denied (the fail-open this guards).
	neither := &logical.Request{
		Operation:     logical.ReadOperation,
		Path:          "x",
		TokenMetadata: map[string]string{"env": "dev", "team": "blue"},
	}
	assert.False(t, cbp.AllowOperation(ctx, neither, &logical.TokenEntry{Metadata: map[string]string{"env": "dev", "team": "blue"}}, false).Allowed,
		"mixed mechanisms must not fail open")

	// Satisfies both gates -> allowed (mixed is conservatively ANDed).
	both := &logical.Request{
		Operation:     logical.ReadOperation,
		Path:          "x",
		TokenMetadata: map[string]string{"env": "prod", "team": "red"},
	}
	assert.True(t, cbp.AllowOperation(ctx, both, &logical.TokenEntry{Metadata: map[string]string{"env": "prod", "team": "red"}}, false).Allowed)
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
			condition = "request.data.ttl_seconds <= 3600 && token.metadata.env == 'prod'"
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
