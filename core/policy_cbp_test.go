// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
)

// Helper function to create a context with root namespace
func testContext() context.Context {
	return namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
}

// Helper function to parse a policy for testing
func testParsePolicy(t testing.TB, rules string) *Policy {
	t.Helper()
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	return policy
}

// TestCBP_ConditionIsIdentityIndependent proves a condition compiles once and is
// evaluated against per-token activation data — never recompiled per identity.
// One CBP, two different tokens, opposite outcomes driven purely by token data.
func TestCBP_ConditionIsIdentityIndependent(t *testing.T) {
	ctx := testContext()
	p := testParsePolicy(t, `path "secret/x" { capabilities = ["read"] condition = "agent.metadata.env == 'prod'" }`)
	cbp, err := NewCBP(ctx, []*Policy{p})
	require.NoError(t, err)

	req := &logical.Request{Operation: logical.ReadOperation, Path: "secret/x"}
	prod := &logical.TokenEntry{Metadata: map[string]string{"env": "prod"}}
	dev := &logical.TokenEntry{Metadata: map[string]string{"env": "dev"}}

	assert.True(t, cbp.AllowOperation(ctx, req, prod, false).Allowed)
	assert.False(t, cbp.AllowOperation(ctx, req, dev, false).Allowed)
}

// TestCBP_CompiledConditionSharedAcrossCallers confirms a conditioned policy is
// parsed — and therefore its CEL program compiled — exactly once, and reused by
// every caller. That reuse is what the no-templated-policies invariant buys: the
// compiled program depends on the policy set alone, never on token identity, so
// one copy can serve everyone.
//
// The CBP assembled from those policies is deliberately *not* shared. Building it
// is microseconds, and a cache of assembled CBPs previously outlived the policy
// it was built from, so a deleted grant went on being enforced. What must be
// shared is the expensive part; what must be fresh is the part that has to
// reflect the current policy.
func TestCBP_CompiledConditionSharedAcrossCallers(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	p := testParsePolicy(t, `path "secret/x" { capabilities = ["read"] condition = "agent.metadata.env == 'prod'" }`)
	p.Name = "cond"
	p.Type = PolicyTypeCBP
	require.NoError(t, ps.SetPolicy(ctx, p, nil))

	names := map[string][]string{namespace.RootNamespaceID: {"cond"}}
	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)

	assert.NotSame(t, first, second, "each caller assembles its own CBP from the current policies")

	// Both assemblies drew on the same parsed policy, which is what holds the
	// compiled CEL program — so the condition was compiled once, not per call.
	cached, ok := ps.tokenPoliciesLRU.Get(ps.cacheKey(namespace.RootNamespace, "cond", PolicyTypeCBP))
	require.True(t, ok, "the parsed policy must stay cached")
	require.Len(t, cached.Paths, 1)
	assert.NotEmpty(t, cached.Paths[0].Permissions.Conditions,
		"the cached policy carries the compiled condition shared by every caller")
}

// =============================================================================
// CBP Creation Tests
// =============================================================================

func TestNewCBP_EmptyPolicies(t *testing.T) {
	ctx := testContext()

	cbp, err := NewCBP(ctx, []*Policy{})
	require.NoError(t, err)
	require.NotNil(t, cbp)
	assert.False(t, cbp.root)
}

func TestNewCBP_NilPolicies(t *testing.T) {
	ctx := testContext()

	cbp, err := NewCBP(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, cbp)
}

func TestNewCBP_NilPolicyInList(t *testing.T) {
	ctx := testContext()

	policies := []*Policy{nil, nil}
	cbp, err := NewCBP(ctx, policies)
	require.NoError(t, err)
	require.NotNil(t, cbp)
}

func TestNewCBP_NoNamespace(t *testing.T) {
	ctx := context.Background()

	_, err := NewCBP(ctx, []*Policy{})
	require.Error(t, err)
}

func TestNewCBP_SinglePolicy(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/*" {
			capabilities = ["read", "list"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)
	require.NotNil(t, cbp)
	assert.False(t, cbp.root)
}

func TestNewCBP_InvalidPolicyType(t *testing.T) {
	ctx := testContext()

	policy := &Policy{
		Name: "invalid",
		Type: PolicyType(99), // Invalid type
	}

	_, err := NewCBP(ctx, []*Policy{policy})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrong type")
}

// =============================================================================
// Root Policy Tests
// =============================================================================

func TestNewCBP_RootPolicy(t *testing.T) {
	ctx := testContext()

	policy := &Policy{
		Name:      "root",
		Type:      PolicyTypeCBP,
		namespace: namespace.RootNamespace,
	}

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)
	require.NotNil(t, cbp)
	assert.True(t, cbp.root)
}

func TestNewCBP_RootPolicyWithOtherPolicies(t *testing.T) {
	ctx := testContext()

	rootPolicy := &Policy{
		Name:      "root",
		Type:      PolicyTypeCBP,
		namespace: namespace.RootNamespace,
	}

	otherPolicy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read"]
		}
	`)

	// Root policy cannot be combined with other policies
	_, err := NewCBP(ctx, []*Policy{rootPolicy, otherPolicy})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "other policies present along with root")
}

func TestCBP_RootAllowsEverything(t *testing.T) {
	ctx := testContext()

	policy := &Policy{
		Name:      "root",
		Type:      PolicyTypeCBP,
		namespace: namespace.RootNamespace,
	}

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Test various paths and operations
	testCases := []struct {
		path      string
		operation logical.Operation
	}{
		{"secret/data/test", logical.ReadOperation},
		{"secret/data/test", logical.CreateOperation},
		{"secret/data/test", logical.UpdateOperation},
		{"secret/data/test", logical.DeleteOperation},
		{"secret/data/test", logical.ListOperation},
		{"sys/mounts", logical.ReadOperation},
		{"any/path/here", logical.ReadOperation},
	}

	for _, tc := range testCases {
		t.Run(tc.path+"_"+string(tc.operation), func(t *testing.T) {
			req := &logical.Request{
				Path:      tc.path,
				Operation: tc.operation,
			}

			result := cbp.AllowOperation(ctx, req, nil, false)
			assert.True(t, result.Allowed)
			assert.True(t, result.IsRoot)
			assert.True(t, result.RootPrivs)
		})
	}
}

// =============================================================================
// Path Matching Tests - Exact Paths
// =============================================================================

func TestCBP_ExactPathMatch(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/mykey" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Exact match should be allowed
	req := &logical.Request{
		Path:      "secret/data/mykey",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	// Different path should not be allowed
	req.Path = "secret/data/otherkey"
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)
}

func TestCBP_ExactPathNoMatch(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/specific" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Partial match should not work
	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)

	// Longer path should not match
	req.Path = "secret/data/specific/extra"
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)
}

// =============================================================================
// Path Matching Tests - Prefix Paths (glob)
// =============================================================================

func TestCBP_PrefixPathMatch(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/*" {
			capabilities = ["read", "list"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	testCases := []struct {
		path    string
		allowed bool
	}{
		{"secret/data/key1", true},
		{"secret/data/key1/nested", true},
		{"secret/data/", true},
		{"secret/data", false}, // No trailing slash or content after prefix
		{"secret/other/key", false},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req := &logical.Request{
				Path:      tc.path,
				Operation: logical.ReadOperation,
			}
			result := cbp.AllowOperation(ctx, req, nil, false)
			assert.Equal(t, tc.allowed, result.Allowed, "path: %s", tc.path)
		})
	}
}

func TestCBP_MultiplePrefixPaths(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read"]
		}
		path "kv/*" {
			capabilities = ["read", "create"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// secret/* should only have read
	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)

	// kv/* should have read and create
	req.Path = "kv/data"
	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)
}

// =============================================================================
// Path Matching Tests - Segment Wildcards (+)
// =============================================================================

func TestCBP_SegmentWildcard(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/+/data" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	testCases := []struct {
		path    string
		allowed bool
	}{
		{"secret/app1/data", true},
		{"secret/app2/data", true},
		{"secret/any-thing/data", true},
		{"secret/data", false},            // Missing segment
		{"secret/app1/data/extra", false}, // Extra segment
		{"secret/app1/metadata", false},   // Different final segment
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req := &logical.Request{
				Path:      tc.path,
				Operation: logical.ReadOperation,
			}
			result := cbp.AllowOperation(ctx, req, nil, false)
			assert.Equal(t, tc.allowed, result.Allowed, "path: %s", tc.path)
		})
	}
}

func TestCBP_MultipleSegmentWildcards(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/+/data/+" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	testCases := []struct {
		path    string
		allowed bool
	}{
		{"secret/app1/data/key1", true},
		{"secret/app2/data/key2", true},
		{"secret/app1/data", false},            // Missing last segment
		{"secret/app1/metadata/key1", false},   // Wrong middle segment
		{"secret/app1/data/key1/extra", false}, // Extra segment
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req := &logical.Request{
				Path:      tc.path,
				Operation: logical.ReadOperation,
			}
			result := cbp.AllowOperation(ctx, req, nil, false)
			assert.Equal(t, tc.allowed, result.Allowed, "path: %s", tc.path)
		})
	}
}

func TestCBP_SegmentWildcardWithGlob(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/+/data/*" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	testCases := []struct {
		path    string
		allowed bool
	}{
		{"secret/app1/data/key1", true},
		{"secret/app2/data/key2/nested", true},
		{"secret/app1/data/", true},
		{"secret/app1/metadata/key", false},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req := &logical.Request{
				Path:      tc.path,
				Operation: logical.ReadOperation,
			}
			result := cbp.AllowOperation(ctx, req, nil, false)
			assert.Equal(t, tc.allowed, result.Allowed, "path: %s", tc.path)
		})
	}
}

// =============================================================================
// Capability Tests
// =============================================================================

func TestCBP_AllCapabilities(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "test/*" {
			capabilities = ["create", "read", "update", "delete", "list", "sudo", "patch", "scan"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	operations := []logical.Operation{
		logical.CreateOperation,
		logical.ReadOperation,
		logical.UpdateOperation,
		logical.DeleteOperation,
		logical.ListOperation,
		logical.PatchOperation,
		logical.ScanOperation,
	}

	for _, op := range operations {
		t.Run(string(op), func(t *testing.T) {
			req := &logical.Request{
				Path:      "test/key",
				Operation: op,
			}
			result := cbp.AllowOperation(ctx, req, nil, false)
			assert.True(t, result.Allowed, "operation: %s", op)
		})
	}

	// Check sudo privilege
	req := &logical.Request{
		Path:      "test/key",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.RootPrivs)
}

func TestCBP_SpecificCapabilities(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "readonly/*" {
			capabilities = ["read"]
		}
		path "writeonly/*" {
			capabilities = ["create", "update"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// readonly path
	req := &logical.Request{
		Path:      "readonly/key",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)

	// writeonly path
	req.Path = "writeonly/key"
	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.ReadOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)
}

func TestCBP_DenyCapability(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/sensitive/*" {
			capabilities = ["deny"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	operations := []logical.Operation{
		logical.CreateOperation,
		logical.ReadOperation,
		logical.UpdateOperation,
		logical.DeleteOperation,
		logical.ListOperation,
	}

	for _, op := range operations {
		t.Run(string(op), func(t *testing.T) {
			req := &logical.Request{
				Path:      "secret/sensitive/key",
				Operation: op,
			}
			result := cbp.AllowOperation(ctx, req, nil, false)
			assert.False(t, result.Allowed, "operation %s should be denied", op)
		})
	}
}

func TestCBP_HelpOperationAlwaysAllowed(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["deny"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.HelpOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)
}

// =============================================================================
// Policy Merging Tests
// =============================================================================

func TestCBP_MergePoliciesAddCapabilities(t *testing.T) {
	ctx := testContext()

	policy1 := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read"]
		}
	`)

	policy2 := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["create", "update"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy1, policy2})
	require.NoError(t, err)

	// Should have combined capabilities
	req := &logical.Request{
		Path:      "secret/key",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.UpdateOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	// But not delete
	req.Operation = logical.DeleteOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)
}

func TestCBP_DenyOverridesAll(t *testing.T) {
	ctx := testContext()

	// First policy allows
	policy1 := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read", "create", "update"]
		}
	`)

	// Second policy denies
	policy2 := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["deny"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy1, policy2})
	require.NoError(t, err)

	// All operations should be denied
	req := &logical.Request{
		Path:      "secret/key",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)

	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)
}

func TestCBP_ExistingDenyNotOverridden(t *testing.T) {
	ctx := testContext()

	// First policy denies
	policy1 := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["deny"]
		}
	`)

	// Second policy tries to allow
	policy2 := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read", "create"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy1, policy2})
	require.NoError(t, err)

	// Should still be denied
	req := &logical.Request{
		Path:      "secret/key",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)
}

// =============================================================================
// Capabilities Method Tests
// =============================================================================

func TestCBP_Capabilities(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read", "list", "create"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	caps := cbp.Capabilities(ctx, "secret/data")
	assert.Contains(t, caps, ReadCapability)
	assert.Contains(t, caps, ListCapability)
	assert.Contains(t, caps, CreateCapability)
	assert.NotContains(t, caps, UpdateCapability)
	assert.NotContains(t, caps, DeleteCapability)
}

func TestCBP_CapabilitiesNoMatch(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	caps := cbp.Capabilities(ctx, "other/path")
	assert.Contains(t, caps, DenyCapability)
	assert.Len(t, caps, 1)
}

func TestCBP_CapabilitiesRoot(t *testing.T) {
	ctx := testContext()

	policy := &Policy{
		Name:      "root",
		Type:      PolicyTypeCBP,
		namespace: namespace.RootNamespace,
	}

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	caps := cbp.Capabilities(ctx, "any/path")
	assert.Contains(t, caps, RootCapability)
	assert.Len(t, caps, 1)
}

// =============================================================================
// List Operation Tests
// =============================================================================

func TestCBP_ListOperation(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data" {
			capabilities = ["list"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// List operation with trailing slash
	req := &logical.Request{
		Path:      "secret/data/",
		Operation: logical.ListOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	// List operation without trailing slash
	req.Path = "secret/data"
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)
}

func TestCBP_ListWithPaginationLimit(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data" {
			capabilities = ["list"]
			pagination_limit = 100
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Within limit
	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ListOperation,
		Data: map[string]interface{}{
			"limit": 50,
		},
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	// Exceeds limit
	req.Data = map[string]interface{}{
		"limit": 200,
	}
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.False(t, result.Allowed)

	// Using "max" keyword
	req.Data = map[string]interface{}{
		"limit": "max",
	}
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)
	assert.Equal(t, "100", req.Data["limit"])
}

// =============================================================================
// Special Operations Tests
// =============================================================================

func TestCBP_RevokeRenewRollbackOperations(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "auth/token/*" {
			capabilities = ["update"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	operations := []logical.Operation{
		logical.RevokeOperation,
		logical.RenewOperation,
		logical.RollbackOperation,
	}

	for _, op := range operations {
		t.Run(string(op), func(t *testing.T) {
			req := &logical.Request{
				Path:      "auth/token/renew",
				Operation: op,
			}
			result := cbp.AllowOperation(ctx, req, nil, false)
			assert.True(t, result.Allowed, "operation %s should use update capability", op)
		})
	}
}

// =============================================================================
// CapCheckOnly Tests
// =============================================================================

func TestCBP_CapCheckOnly(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read", "sudo"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ReadOperation,
	}

	// With capCheckOnly = true
	result := cbp.AllowOperation(ctx, req, nil, true)
	assert.True(t, result.RootPrivs)
	assert.Equal(t, ReadCapabilityInt|SudoCapabilityInt, result.CapabilitiesBitmap)
	assert.False(t, result.Allowed) // Allowed is not set with capCheckOnly
}

// =============================================================================
// Leading Slash Handling Tests
// =============================================================================

func TestCBP_LeadingSlashHandling(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "/secret/data" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Path with leading slash in request
	req := &logical.Request{
		Path:      "/secret/data",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)

	// Path without leading slash
	req.Path = "secret/data"
	result = cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)
}

// =============================================================================
// Policy Parsing Tests
// =============================================================================

func TestParseCBPPolicy_Basic(t *testing.T) {
	rules := `
		name = "test-policy"
		path "secret/*" {
			capabilities = ["read", "list"]
		}
	`

	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	require.NotNil(t, policy)

	assert.Equal(t, "test-policy", policy.Name)
	assert.Equal(t, PolicyTypeCBP, policy.Type)
	assert.Len(t, policy.Paths, 1)
	assert.Equal(t, "secret/", policy.Paths[0].Path)
	assert.True(t, policy.Paths[0].IsPrefix)
}

func TestParseCBPPolicy_InvalidCapability(t *testing.T) {
	rules := `
		path "secret/*" {
			capabilities = ["read", "invalid"]
		}
	`

	_, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid capability")
}

func TestParseCBPPolicy_InvalidHCL(t *testing.T) {
	rules := `this is not valid HCL`

	_, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.Error(t, err)
}

func TestParseCBPPolicy_InvalidWildcard(t *testing.T) {
	rules := `
		path "secret/+*" {
			capabilities = ["read"]
		}
	`

	_, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "+*")
}

// =============================================================================
// Granting Policies Tests
// =============================================================================

func TestCBP_GrantingPolicies(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		name = "test-policy"
		path "secret/*" {
			capabilities = ["read"]
		}
	`)
	policy.Name = "test-policy"

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, nil, false)
	assert.True(t, result.Allowed)
	assert.Len(t, result.GrantingPolicies, 1)
	assert.Equal(t, "test-policy", result.GrantingPolicies[0].Name)
}

// =============================================================================
// performPolicyChecks Tests
// =============================================================================

func TestPerformPolicyChecks_Basic(t *testing.T) {
	ctx := testContext()
	core := createTestCore(t)
	defer core.tokenStore.Close()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ReadOperation,
	}

	result := core.performPolicyChecks(ctx, cbp, nil, req, &PolicyCheckOpts{})
	assert.True(t, result.Allowed)
	assert.NotNil(t, result.CBPResults)
}

func TestPerformPolicyChecks_Unauth(t *testing.T) {
	ctx := testContext()
	core := createTestCore(t)
	defer core.tokenStore.Close()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["deny"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ReadOperation,
	}

	// With Unauth=true, CBP checks are skipped
	result := core.performPolicyChecks(ctx, cbp, nil, req, &PolicyCheckOpts{Unauth: true})
	assert.True(t, result.Allowed)
}

func TestPerformPolicyChecks_RootPrivsRequired(t *testing.T) {
	ctx := testContext()
	core := createTestCore(t)
	defer core.tokenStore.Close()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ReadOperation,
	}

	// Root privs required but not granted
	result := core.performPolicyChecks(ctx, cbp, nil, req, &PolicyCheckOpts{RootPrivsRequired: true})
	assert.False(t, result.Allowed)
}

func TestPerformPolicyChecks_RootPrivsGranted(t *testing.T) {
	ctx := testContext()
	core := createTestCore(t)
	defer core.tokenStore.Close()

	policy := testParsePolicy(t, `
		path "secret/*" {
			capabilities = ["read", "sudo"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	req := &logical.Request{
		Path:      "secret/data",
		Operation: logical.ReadOperation,
	}

	// Root privs required and granted via sudo
	result := core.performPolicyChecks(ctx, cbp, nil, req, &PolicyCheckOpts{RootPrivsRequired: true})
	assert.True(t, result.Allowed)
	assert.True(t, result.RootPrivs)
}

// =============================================================================
// CBP() re-parse reuse
// =============================================================================

// TestCBP_ReusesCachedParse verifies that CBP() reuses the parse already
// performed by GetPolicy instead of re-parsing Raw on every call.
//
// The cached *Policy is constructed so its parsed Paths intentionally diverge
// from its Raw text: the cache grants "secret/cached" while Raw would grant
// "secret/raw". If CBP() were to re-parse Raw, "secret/raw" would be allowed;
// because it reuses the cached parse, only "secret/cached" is allowed.
func TestCBP_ReusesCachedParse(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	cached := testParsePolicy(t, `path "secret/cached" { capabilities = ["read"] }`)
	cached.Name = "diverged"
	cached.Type = PolicyTypeCBP
	cached.Raw = `path "secret/raw" { capabilities = ["read"] }`
	cached.namespace = namespace.RootNamespace
	require.NotNil(t, cached.Paths)

	// Seed the LRU directly so GetPolicy returns this cached *Policy on the
	// cache-hit path (storage is never consulted).
	idx := ps.cacheKey(namespace.RootNamespace, "diverged", PolicyTypeCBP)
	ps.tokenPoliciesLRU.Add(idx, cached)

	cbp, err := ps.CBP(ctx, map[string][]string{namespace.RootNamespaceID: {"diverged"}})
	require.NoError(t, err)

	assert.Contains(t, cbp.Capabilities(ctx, "secret/cached"), ReadCapability,
		"cached parse should be reused")
	assert.NotContains(t, cbp.Capabilities(ctx, "secret/raw"), ReadCapability,
		"Raw must not be re-parsed when Paths is already populated")
}

// TestCBP_ParsesAdditionalPolicyWithoutPaths verifies the parse fallback: a
// prefetched policy that arrives without parsed Paths is still parsed from Raw
// so it contributes its rules.
func TestCBP_ParsesAdditionalPolicyWithoutPaths(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// No Paths set; only Raw. The guard must fall back to parsing Raw.
	extra := &Policy{
		Name:      "prefetched",
		Type:      PolicyTypeCBP,
		Raw:       `path "secret/extra" { capabilities = ["read"] }`,
		namespace: namespace.RootNamespace,
	}
	require.Nil(t, extra.Paths)

	cbp, err := ps.CBP(ctx, map[string][]string{}, extra)
	require.NoError(t, err)

	assert.Contains(t, cbp.Capabilities(ctx, "secret/extra"), ReadCapability,
		"prefetched policy without Paths must be parsed from Raw")
}

// A policy with no stanza is parsed once, like any other: its Paths are empty,
// never nil, which CBP() would read as "never parsed" and parse again on every
// request. Root is synthesized the same way. An emptied built-in, the
// documented way to turn discovery off, therefore costs no more to compile
// than the seeded one.
func TestCBP_EmptyPolicyParsedOnce(t *testing.T) {
	empty, err := ParseCBPPolicy(namespace.RootNamespace, "# no stanza\n")
	require.NoError(t, err)
	assert.NotNil(t, empty.Paths)

	c := createTestCore(t)
	ctx := rootCtx()
	root, err := c.policyStore.GetPolicy(ctx, "root", PolicyTypeCBP)
	require.NoError(t, err)
	assert.NotNil(t, root.Paths)

	te := &logical.TokenEntry{NamespaceID: namespace.RootNamespaceID}
	compileAllocs := func() float64 {
		return testing.AllocsPerRun(50, func() {
			if _, err := c.buildCBP(ctx, te, true); err != nil {
				t.Fatal(err)
			}
		})
	}
	seeded := compileAllocs()

	emptied, err := ParseCBPPolicy(namespace.RootNamespace, "# discovery off\n")
	require.NoError(t, err)
	emptied.Name, emptied.Type = builtinCBPPolicy, PolicyTypeCBP
	require.NoError(t, c.policyStore.SetPolicy(ctx, emptied, nil))
	assert.LessOrEqual(t, compileAllocs(), seeded, "an emptied built-in is not parsed again per request")
}

// =============================================================================
// CBP compilation is never served from a stale cache
// =============================================================================

// setStoredPolicy writes a policy under the given name and returns nothing —
// the point is the side effect on the store, which is what these tests vary.
func setStoredPolicy(t *testing.T, ps *PolicyStore, ctx context.Context, name, rules string) {
	t.Helper()
	p := testParsePolicy(t, rules)
	p.Name = name
	p.Type = PolicyTypeCBP
	require.NoError(t, ps.SetPolicy(ctx, p, nil))
}

// TestCBP_RecreatedPolicyIsEnforced is the regression test for a compiled-policy
// cache that was keyed on policy identity and version. Deleting a policy resets
// its version, so recreating it under the same name collided with the entry
// compiled before the delete — and the deleted policy went on being enforced.
//
// The consequence was that removing a permission did not revoke it, while
// reading the policy back returned the new text: the stored policy and the
// enforced policy disagreed, and the API confirmed the operator's intent.
func TestCBP_RecreatedPolicyIsEnforced(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	names := map[string][]string{namespace.RootNamespaceID: {"recreated"}}

	setStoredPolicy(t, ps, ctx, "recreated", `path "secret/old" { capabilities = ["read"] }`)
	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	require.Contains(t, first.Capabilities(ctx, "secret/old"), ReadCapability)

	// Delete and recreate under the same name with a different grant. The
	// version counter restarts here, which is what made the old key collide.
	require.NoError(t, ps.DeletePolicy(ctx, "recreated", PolicyTypeCBP))
	setStoredPolicy(t, ps, ctx, "recreated", `path "secret/new" { capabilities = ["read"] }`)

	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.Contains(t, second.Capabilities(ctx, "secret/new"), ReadCapability,
		"the recreated policy must be the one enforced")
	assert.NotContains(t, second.Capabilities(ctx, "secret/old"), ReadCapability,
		"the deleted policy's grant must not survive its deletion")
}

// TestCBP_DeletedPolicyIsNotEnforced covers the plainer half: a deletion with no
// replacement. The policy simply leaves the set, and nothing it granted remains.
func TestCBP_DeletedPolicyIsNotEnforced(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	setStoredPolicy(t, ps, ctx, "keeper", `path "secret/keep" { capabilities = ["read"] }`)
	setStoredPolicy(t, ps, ctx, "goner", `path "secret/gone" { capabilities = ["read"] }`)

	names := map[string][]string{namespace.RootNamespaceID: {"keeper", "goner"}}
	before, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	require.Contains(t, before.Capabilities(ctx, "secret/gone"), ReadCapability)

	require.NoError(t, ps.DeletePolicy(ctx, "goner", PolicyTypeCBP))

	after, err := ps.CBP(ctx, map[string][]string{namespace.RootNamespaceID: {"keeper"}})
	require.NoError(t, err)
	assert.Contains(t, after.Capabilities(ctx, "secret/keep"), ReadCapability)
	assert.NotContains(t, after.Capabilities(ctx, "secret/gone"), ReadCapability)
}

// TestCBP_EditedPolicyIsEnforced pins the case that always worked, so a
// regression in the ordinary edit path is not mistaken for the delete-recreate
// bug returning.
func TestCBP_EditedPolicyIsEnforced(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	names := map[string][]string{namespace.RootNamespaceID: {"edited"}}

	setStoredPolicy(t, ps, ctx, "edited", `path "secret/a" { capabilities = ["read"] }`)
	_, err := ps.CBP(ctx, names)
	require.NoError(t, err)

	setStoredPolicy(t, ps, ctx, "edited", `path "secret/b" { capabilities = ["read"] }`)
	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)

	assert.Contains(t, second.Capabilities(ctx, "secret/b"), ReadCapability)
	assert.NotContains(t, second.Capabilities(ctx, "secret/a"), ReadCapability)
}

// TestCBP_ExpiredPathIsDropped verifies a per-path expiration takes effect. This
// was previously entangled with a cache time-bound; without the cache it is just
// a property of compilation, which is where it belonged.
func TestCBP_ExpiredPathIsDropped(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	p := &Policy{
		Name:      "expiring",
		Type:      PolicyTypeCBP,
		namespace: namespace.RootNamespace,
		Paths: []*PathRules{{
			Path:         "secret/temp",
			Capabilities: []string{ReadCapability},
			Permissions:  &CBPPermissions{CapabilitiesBitmap: ReadCapabilityInt},
			Expiration:   time.Now().Add(50 * time.Millisecond),
		}},
	}
	ps.tokenPoliciesLRU.Add(ps.cacheKey(namespace.RootNamespace, "expiring", PolicyTypeCBP), p)

	names := map[string][]string{namespace.RootNamespaceID: {"expiring"}}
	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	require.Contains(t, first.Capabilities(ctx, "secret/temp"), ReadCapability)

	time.Sleep(80 * time.Millisecond)

	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.NotContains(t, second.Capabilities(ctx, "secret/temp"), ReadCapability,
		"an expired path must not be granted")
}

// TestCBP_ConcurrentCompilation exercises compilation and evaluation from many
// goroutines at once, under the race detector.
func TestCBP_ConcurrentCompilation(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	setStoredPolicy(t, ps, ctx, "concurrent", `
		path "secret/a" { capabilities = ["read", "list"] }
		path "secret/b/*" { capabilities = ["read"] }
	`)

	names := map[string][]string{namespace.RootNamespaceID: {"concurrent"}}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cbp, err := ps.CBP(ctx, names)
			if err != nil {
				t.Error(err)
				return
			}
			req := &logical.Request{Operation: logical.ReadOperation, Path: "secret/a"}
			cbp.AllowOperation(ctx, req, nil, false)
			cbp.Capabilities(ctx, "secret/b/x")
		}()
	}
	wg.Wait()
}

// BenchmarkNewCBP measures what a compiled-CBP cache would save. It is kept so
// the next person to propose one has the number: a cache here previously cost a
// revocation bug, and the work it avoided is small enough to be noise beside the
// credential mint and upstream round trip on the same request.
func BenchmarkNewCBP(b *testing.B) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	rules := `
path "prov/gateway*" {
  capabilities = ["read","create","update","delete","list"]
}
path "prov/role/+/gateway*" {
  capabilities = ["read","create","update","delete","list"]
}
path "other/*" { capabilities = ["read"] }
`
	for _, n := range []int{1, 3} {
		policies := make([]*Policy, 0, n)
		for i := 0; i < n; i++ {
			p, err := ParseCBPPolicy(namespace.RootNamespace, rules)
			if err != nil {
				b.Fatal(err)
			}
			p.Name = fmt.Sprintf("p%d", i)
			policies = append(policies, p)
		}
		b.Run(fmt.Sprintf("%d-policies", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := NewCBP(ctx, policies); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	// A compile is per request — CBP() rebuilds from cached policies every
	// time — so what a contract adds here is paid on every call, not once.
	// Compared against 2-policies rather than 3, this isolates the second
	// index from the extra document.
	mcpRules := `
path "prov/gateway*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["get_repository", "list_issues"] }
}
path "prov/role/+/gateway*" {
  methods { allowed = ["tools/list", "tools/call"] }
  tools { allowed = ["get_repository", "list_issues"] }
}
`
	mixed := make([]*Policy, 0, 3)
	for i := 0; i < 2; i++ {
		p, err := ParseCBPPolicy(namespace.RootNamespace, rules)
		if err != nil {
			b.Fatal(err)
		}
		p.Name = fmt.Sprintf("p%d", i)
		mixed = append(mixed, p)
	}
	contract, err := ParseMCPPolicy(namespace.RootNamespace, mcpRules)
	if err != nil {
		b.Fatal(err)
	}
	contract.Name = "contract"

	b.Run("2-policies", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := NewCBP(ctx, mixed); err != nil {
				b.Fatal(err)
			}
		}
	})

	withContract := append(append([]*Policy(nil), mixed...), contract)
	b.Run("2-policies+1-mcp", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := NewCBP(ctx, withContract); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestCBP_CompilationIsOrderIndependent pins that a token's policies compile to
// the same result however they were gathered.
//
// Compilation is not commutative: for a given path, the first policy carrying a
// list_scan_response_keys_filter_path wins. Policies are gathered by ranging a
// map keyed by namespace, so when a token draws policies from more than one
// namespace their relative order is randomised per call — and two policies
// disagreeing on that field would otherwise yield a different filter from one
// request to the next.
//
// Within a single namespace the order comes from a slice and is already stable,
// which is why this test spans two.
func TestCBP_CompilationIsOrderIndependent(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	rootCtx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	otherNS := &namespace.Namespace{Path: "other/"}
	require.NoError(t, core.namespaceStore.SetNamespace(rootCtx, otherNS))
	otherCtx := namespace.ContextWithNamespace(context.Background(), otherNS)

	filterPolicy := func(which string) string {
		return `
path "secret/shared" {
  capabilities = ["list"]
  list_scan_response_keys_filter_path = "secret/from-` + which + `/{{ .key }}"
}`
	}

	// One policy per namespace, disagreeing on the filter for the same path.
	setStoredPolicy(t, ps, rootCtx, "filter-root", filterPolicy("root"))

	otherPolicy := testParsePolicy(t, filterPolicy("other"))
	otherPolicy.Name = "filter-other"
	otherPolicy.Type = PolicyTypeCBP
	otherPolicy.namespace = otherNS
	require.NoError(t, ps.SetPolicy(otherCtx, otherPolicy, nil))

	names := map[string][]string{
		namespace.RootNamespaceID: {"filter-root"},
		otherNS.ID:                {"filter-other"},
	}

	// Repeat: an order-dependent result shows up as disagreement across runs,
	// since the map range that gathers these is randomised each time.
	seen := map[string]int{}
	for i := 0; i < 64; i++ {
		cbp, err := ps.CBP(rootCtx, names)
		require.NoError(t, err)
		res := cbp.AllowOperation(rootCtx,
			&logical.Request{Operation: logical.ListOperation, Path: "secret/shared"}, nil, false)
		require.True(t, res.Allowed, "the shared path must be listable")
		seen[res.ResponseKeysFilterPath]++
	}

	assert.Len(t, seen, 1,
		"the filter path must not depend on the order policies were gathered in, got %v", seen)
}

// =============================================================================
// A compile shares the parsed policies it reads, and never writes them
// =============================================================================

// finalizedPolicy parses rules into a policy of the given name and type,
// finalized as the policy store finalizes what it caches.
func finalizedPolicy(t *testing.T, name string, typ PolicyType, rules string) *Policy {
	t.Helper()
	var p *Policy
	if typ == PolicyTypeMCP {
		p = testParseMCPPolicy(t, rules)
	} else {
		p = testParsePolicy(t, rules)
	}
	p.Name, p.Type = name, typ
	p.finalize()
	return p
}

// permsSnapshot records everything a compile could write in a parsed stanza:
// its scalars, the length, capacity and backing array of its slices, and the
// attribution of its MCP rule-sets.
type permsSnapshot struct {
	caps          uint32
	pagination    int
	filterPath    string
	conditions    int
	conditionsCap int
	conditionsArr **compiledCondition
	conditionsAll []*compiledCondition
	mcp           int
	mcpCap        int
	mcpArr        **CBPMCPRules
	mcpAll        []*CBPMCPRules
	sources       []string
	owner         *Policy
	extra         int
}

func snapshotPerms(p *CBPPermissions) permsSnapshot {
	s := permsSnapshot{
		caps: p.CapabilitiesBitmap, pagination: p.PaginationLimit, filterPath: p.ResponseKeysFilterPath,
		conditions: len(p.Conditions), conditionsCap: cap(p.Conditions),
		mcp: len(p.MCP), mcpCap: cap(p.MCP),
		owner: p.owner, extra: len(p.extra),
	}
	// The address of element 0 of the full-capacity slice identifies the
	// backing array, and its contents up to capacity show an append written
	// into spare room, which leaves length and array unchanged.
	if cap(p.Conditions) > 0 {
		all := p.Conditions[:cap(p.Conditions)]
		s.conditionsArr, s.conditionsAll = &all[0], slices.Clone(all)
	}
	if cap(p.MCP) > 0 {
		all := p.MCP[:cap(p.MCP)]
		s.mcpArr, s.mcpAll = &all[0], slices.Clone(all)
	}
	for _, m := range p.MCP {
		s.sources = append(s.sources, m.SourcePolicy)
	}
	return s
}

func snapshotPolicies(policies ...*Policy) []permsSnapshot {
	var out []permsSnapshot
	for _, p := range policies {
		for _, pc := range p.Paths {
			out = append(out, snapshotPerms(pc.Permissions))
		}
	}
	return out
}

func grantingNames(in []sdklogical.PolicyInfo) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.Name)
	}
	return out
}

// TestCBP_ParsedPoliciesUntouched pins that compiling and evaluating never
// writes the parsed policies, which the policy cache shares across requests.
// Every merge a compile performs is exercised: capabilities, a deny collapse,
// pagination, the filter path and conditions at an exact key, a prefix and a
// segment wildcard, two MCP policies at one key and one MCP policy with two
// stanzas at one key.
func TestCBP_ParsedPoliciesUntouched(t *testing.T) {
	ctx := testContext()
	a := finalizedPolicy(t, "a", PolicyTypeCBP, `
path "secret/x" {
  capabilities = ["read", "list"]
  condition = "request.client_ip != ''"
  pagination_limit = 10
  list_scan_response_keys_filter_path = "secret/from-a/{{ .key }}"
}
path "pre/*" { capabilities = ["read"] }
path "seg/+/x" { capabilities = ["read"] }
`)
	b := finalizedPolicy(t, "b", PolicyTypeCBP, `
path "secret/x" {
  capabilities = ["update"]
  condition = "request.client_ip == '1.1.1.1'"
  pagination_limit = 5
}
path "pre/*" { capabilities = ["deny"] }
path "seg/+/x" { capabilities = ["update"] }
`)
	c := finalizedPolicy(t, "c", PolicyTypeCBP, `path "secret/x" { capabilities = ["delete"] }`)
	m1 := finalizedPolicy(t, "m1", PolicyTypeMCP, `
path "mcp/x" {
  methods {
    allowed = ["tools/call"]
  }
  tools {
    allowed = ["a"]
  }
}
path "mcp/x" {
  methods {
    allowed = ["tools/call"]
  }
  tools {
    allowed = ["b"]
  }
}
`)
	m2 := finalizedPolicy(t, "m2", PolicyTypeMCP, `
path "mcp/x" {
  methods {
    allowed = ["tools/call"]
  }
  tools {
    allowed = ["c"]
  }
}
`)

	// The parser sizes its slices exactly, so an append into one reallocates
	// anyway. Spare room makes an append written in place observable.
	for _, p := range []*Policy{a, m1} {
		for _, pc := range p.Paths {
			pc.Permissions.Conditions = slices.Grow(pc.Permissions.Conditions, 2)
			pc.Permissions.MCP = slices.Grow(pc.Permissions.MCP, 2)
		}
	}

	before := snapshotPolicies(a, b, c, m1, m2)
	for i := 0; i < 3; i++ {
		cbp, err := NewCBP(ctx, []*Policy{a, b, c, m1, m2})
		require.NoError(t, err)
		cbp.AllowOperation(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "secret/x", ClientIP: "1.1.1.1"}, nil, false)
		cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "pre/zz"}, nil, false)
		cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "seg/q/x"}, nil, false)
		sets := cbp.mcpRulesForPath("mcp/x")
		require.Len(t, sets, 3)
		assert.Equal(t, []string{"m1", "m1", "m2"}, []string{sets[0].SourcePolicy, sets[1].SourcePolicy, sets[2].SourcePolicy})
		assert.True(t, mcpListItemAllowed(sets, "tools/call", "c"))

		for _, order := range [][]*Policy{{m2, m1}, {m1}} {
			_, err := NewCBP(ctx, order)
			require.NoError(t, err)
		}
	}
	assert.Equal(t, before, snapshotPolicies(a, b, c, m1, m2))
}

// TestCBP_GrantingPoliciesByCapability pins which policies a merged path names:
// those that granted the requested capability, owner first, whatever else the
// path's other policies grant.
func TestCBP_GrantingPoliciesByCapability(t *testing.T) {
	ctx := testContext()
	a := finalizedPolicy(t, "a", PolicyTypeCBP, `
path "secret/x" { capabilities = ["read", "update"] }
path "pre/*" { capabilities = ["read"] }
`)
	b := finalizedPolicy(t, "b", PolicyTypeCBP, `
path "secret/x" { capabilities = ["update", "delete"] }
path "pre/*" { capabilities = ["deny"] }
`)

	cbp, err := NewCBP(ctx, []*Policy{a, b})
	require.NoError(t, err)
	granting := func(op logical.Operation, path string) []string {
		res := cbp.AllowOperation(ctx, &logical.Request{Operation: op, Path: path}, nil, false)
		require.True(t, res.Allowed, "%s %s", op, path)
		return grantingNames(res.GrantingPolicies)
	}
	assert.Equal(t, []string{"a"}, granting(logical.ReadOperation, "secret/x"))
	assert.Equal(t, []string{"a", "b"}, granting(logical.UpdateOperation, "secret/x"))
	assert.Equal(t, []string{"b"}, granting(logical.DeleteOperation, "secret/x"))

	res := cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "pre/zz"}, nil, false)
	assert.False(t, res.Allowed, "a deny collapses the path")
	assert.Empty(t, res.GrantingPolicies)

	// The same policy listed twice is named twice, as before.
	twice, err := NewCBP(ctx, []*Policy{a, a})
	require.NoError(t, err)
	res = twice.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "secret/x"}, nil, false)
	assert.Equal(t, []string{"a", "a"}, grantingNames(res.GrantingPolicies))

	// A grant shared by several policies is this request's own slice.
	merged := cbp.AllowOperation(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "secret/x"}, nil, false)
	again := cbp.AllowOperation(ctx, &logical.Request{Operation: logical.UpdateOperation, Path: "secret/x"}, nil, false)
	assert.NotSame(t, &merged.GrantingPolicies[0], &again.GrantingPolicies[0])
}

// TestCBP_GrantingPoliciesShared pins the sharing CBPResults.GrantingPolicies
// documents: a sole granter's answer is its cached policy's slice, and root's is
// the package-level one, so a consumer must never write into it.
func TestCBP_GrantingPoliciesShared(t *testing.T) {
	ctx := testContext()
	a := finalizedPolicy(t, "a", PolicyTypeCBP, `path "secret/x" { capabilities = ["read"] }`)
	cbp, err := NewCBP(ctx, []*Policy{a})
	require.NoError(t, err)
	res := cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "secret/x"}, nil, false)
	require.True(t, res.Allowed)
	require.Len(t, res.GrantingPolicies, 1)
	assert.Same(t, &a.info[0], &res.GrantingPolicies[0])
	assert.Equal(t, []sdklogical.PolicyInfo{{Name: "a", NamespaceId: namespace.RootNamespaceID, NamespacePath: "", Type: "cbp"}}, res.GrantingPolicies)

	root := finalizedPolicy(t, "root", PolicyTypeCBP, "")
	rootCBP, err := NewCBP(ctx, []*Policy{root})
	require.NoError(t, err)
	res = rootCBP.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "anything"}, nil, false)
	require.Len(t, res.GrantingPolicies, 1)
	assert.Same(t, &rootGrantingPolicies[0], &res.GrantingPolicies[0])

	// A policy never finalized is still named, from a slice of its own.
	hand := testParsePolicy(t, `path "secret/y" { capabilities = ["read"] }`)
	hand.Name = "hand"
	handCBP, err := NewCBP(ctx, []*Policy{hand})
	require.NoError(t, err)
	res = handCBP.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "secret/y"}, nil, false)
	assert.Equal(t, []string{"hand"}, grantingNames(res.GrantingPolicies))
	assert.Nil(t, hand.info, "a compile does not finalize a shared policy")
}

// TestCBP_MCPSourcePolicy pins the attribution of MCP rule-sets, whichever way
// the policy reached the compile: loaded from the store, finalized, or built by
// hand and never finalized. A hand-built policy's own rule-sets stay unstamped.
func TestCBP_MCPSourcePolicy(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	rules := func(tool string) string {
		return `
path "mcp/x" {
  methods {
    allowed = ["tools/call"]
  }
  tools {
    allowed = ["` + tool + `"]
  }
}`
	}

	stored := testParseMCPPolicy(t, rules("a"))
	stored.Name, stored.Type = "stored", PolicyTypeMCP
	require.NoError(t, ps.SetPolicy(ctx, stored, nil))
	ps.tokenPoliciesLRU.Purge()
	loaded, err := ps.GetPolicy(ctx, "stored", PolicyTypeMCP)
	require.NoError(t, err)

	prefetched := finalizedPolicy(t, "prefetched", PolicyTypeMCP, rules("b"))
	hand := testParseMCPPolicy(t, rules("c"))
	hand.Name, hand.Type = "hand", PolicyTypeMCP

	for _, tc := range []struct {
		policy *Policy
		want   string
	}{{loaded, "stored"}, {prefetched, "prefetched"}, {hand, "hand"}} {
		cbp, err := NewCBP(ctx, []*Policy{tc.policy})
		require.NoError(t, err)
		sets := cbp.mcpRulesForPath("mcp/x")
		require.Len(t, sets, 1)
		assert.Equal(t, tc.want, sets[0].SourcePolicy)
	}
	assert.Equal(t, "", hand.Paths[0].Permissions.MCP[0].SourcePolicy)

	cbp, err := NewCBP(ctx, []*Policy{loaded, hand, prefetched})
	require.NoError(t, err)
	sets := cbp.mcpRulesForPath("mcp/x")
	require.Len(t, sets, 3)
	assert.Equal(t, []string{"stored", "hand", "prefetched"}, []string{sets[0].SourcePolicy, sets[1].SourcePolicy, sets[2].SourcePolicy})
	assert.Equal(t, "", hand.Paths[0].Permissions.MCP[0].SourcePolicy)
}

// TestCBP_MCPEditIsEnforced pins that an edited MCP policy governs the next
// compile, now that the index holds the cached policy's rule-sets instead of a
// copy of them.
func TestCBP_MCPEditIsEnforced(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	names := map[string][]string{namespace.RootNamespaceID: {"contract"}}
	write := func(tool string) {
		p := testParseMCPPolicy(t, `
path "mcp/x" {
  methods {
    allowed = ["tools/call"]
  }
  tools {
    allowed = ["`+tool+`"]
  }
}`)
		p.Name, p.Type = "contract", PolicyTypeMCP
		require.NoError(t, ps.SetPolicy(ctx, p, nil))
	}

	write("old")
	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	require.True(t, mcpListItemAllowed(first.mcpRulesForPath("mcp/x"), "tools/call", "old"))

	write("new")
	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	sets := second.mcpRulesForPath("mcp/x")
	assert.True(t, mcpListItemAllowed(sets, "tools/call", "new"))
	assert.False(t, mcpListItemAllowed(sets, "tools/call", "old"))

	require.NoError(t, ps.DeletePolicy(ctx, "contract", PolicyTypeMCP))
	third, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.Empty(t, third.mcpRulesForPath("mcp/x"))
}

// TestCBP_ConcurrentCompileWhileWriting compiles and evaluates from many
// goroutines while another rewrites and deletes the policies they compile from,
// under the race detector. The policies meet at every key kind, so each compile
// runs every merge: capabilities with conditions at an exact key, a deny
// collapse at a prefix, a segment wildcard, and three MCP rule-sets at one key,
// two of them stanzas of one policy.
func TestCBP_ConcurrentCompileWhileWriting(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	rules := map[string]struct {
		typ  PolicyType
		body string
	}{
		"cbp-a": {PolicyTypeCBP, `
path "secret/a" {
  capabilities = ["read", "list"]
  condition = "request.client_ip != ''"
}
path "pre/*" { capabilities = ["read"] }
path "seg/+/x" { capabilities = ["read"] }
`},
		"cbp-b": {PolicyTypeCBP, `
path "secret/a" {
  capabilities = ["update"]
  condition = "request.client_ip == '1.1.1.1'"
}
path "pre/*" { capabilities = ["deny"] }
path "seg/+/x" { capabilities = ["update"] }
`},
		"mcp-a": {PolicyTypeMCP, `
path "mcp/x" {
  methods {
    allowed = ["tools/list", "tools/call"]
  }
  tools {
    allowed = ["get_*"]
  }
}
path "mcp/x" {
  methods {
    allowed = ["tools/list", "tools/call"]
  }
  tools {
    allowed = ["list_*"]
  }
}`},
		"mcp-b": {PolicyTypeMCP, `
path "mcp/x" {
  methods {
    allowed = ["tools/list", "tools/call"]
  }
  tools {
    allowed = ["search_*"]
  }
}`},
	}
	// write reports instead of failing: it also runs on the writer goroutine.
	write := func(name string) {
		r := rules[name]
		var p *Policy
		var err error
		if r.typ == PolicyTypeMCP {
			p, err = ParseMCPPolicy(namespace.RootNamespace, r.body)
		} else {
			p, err = ParseCBPPolicy(namespace.RootNamespace, r.body)
		}
		if err == nil {
			p.Name, p.Type = name, r.typ
			err = ps.SetPolicy(ctx, p, nil)
		}
		if err != nil {
			t.Error(err)
		}
	}
	for name := range rules {
		write(name)
	}
	names := map[string][]string{namespace.RootNamespaceID: {"cbp-a", "cbp-b", "mcp-a", "mcp-b", "cbp-a"}}

	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = ps.DeletePolicy(ctx, "cbp-b", PolicyTypeCBP)
			_ = ps.DeletePolicy(ctx, "mcp-a", PolicyTypeMCP)
			write("cbp-b")
			write("mcp-a")
			write("mcp-b")
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				cbp, err := ps.CBP(ctx, names)
				if err != nil {
					t.Error(err)
					return
				}
				for _, req := range []*logical.Request{
					{Operation: logical.ReadOperation, Path: "secret/a", ClientIP: "1.1.1.1"},
					{Operation: logical.UpdateOperation, Path: "secret/a", ClientIP: "1.1.1.1"},
					{Operation: logical.ReadOperation, Path: "pre/zz"},
					{Operation: logical.UpdateOperation, Path: "seg/q/x"},
				} {
					cbp.AllowOperation(ctx, req, nil, false)
				}
				mcpListItemAllowed(cbp.mcpRulesForPath("mcp/x"), "tools/list", "search_issues")
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-writerDone
}

// TestCBP_ForNamespaceMatchesCBP pins that the request path's entry compiles
// what CBP() compiles for one namespace: the same grants, the same granting
// policies in the same order, and the same first-wins filter path, whatever
// order the names arrive in.
func TestCBP_ForNamespaceMatchesCBP(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	for _, which := range []string{"b", "a"} {
		setStoredPolicy(t, ps, ctx, "filter-"+which, `
path "secret/shared" {
  capabilities = ["list"]
  list_scan_response_keys_filter_path = "secret/from-`+which+`/{{ .key }}"
}`)
	}
	extra := finalizedPolicy(t, "extra", PolicyTypeCBP, `path "secret/shared" { capabilities = ["list"] }`)
	list := &logical.Request{Operation: logical.ListOperation, Path: "secret/shared"}

	want, err := ps.CBP(ctx, map[string][]string{namespace.RootNamespaceID: {"filter-b", "filter-a"}}, extra)
	require.NoError(t, err)
	wantRes := want.AllowOperation(ctx, list, nil, false)
	require.True(t, wantRes.Allowed)

	for _, names := range [][]string{{"filter-b", "filter-a"}, {"filter-a", "filter-b"}} {
		got, err := ps.cbpForNamespace(ctx, names, []*Policy{extra})
		require.NoError(t, err)
		res := got.AllowOperation(ctx, list, nil, false)
		require.True(t, res.Allowed)
		assert.Equal(t, wantRes.ResponseKeysFilterPath, res.ResponseKeysFilterPath)
		assert.Equal(t, grantingNames(wantRes.GrantingPolicies), grantingNames(res.GrantingPolicies))
	}
	assert.Equal(t, []string{"filter-a", "filter-b", "extra"}, grantingNames(wantRes.GrantingPolicies))
}

// TestCBP_StoredNameAttributed pins that a policy loaded from the store is
// attributed by the name it is stored under, never by a name written in its
// body. The granting-policies slice is built once, when the policy is cached,
// so it must be built after the store's name has replaced the parsed one.
func TestCBP_StoredNameAttributed(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	setStoredPolicy(t, ps, ctx, "good", `
name = "evil"
path "secret/x" { capabilities = ["read"] }
`)
	contract := testParseMCPPolicy(t, `
name = "evil"
path "mcp/x" {
  methods {
    allowed = ["tools/call"]
  }
  tools {
    allowed = ["get_*"]
  }
}`)
	contract.Name, contract.Type = "good-mcp", PolicyTypeMCP
	require.NoError(t, ps.SetPolicy(ctx, contract, nil))

	// Purged, so both are loaded and parsed from storage, not served as written.
	ps.tokenPoliciesLRU.Purge()
	cbp, err := ps.CBP(ctx, map[string][]string{namespace.RootNamespaceID: {"good", "good-mcp"}})
	require.NoError(t, err)

	res := cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "secret/x"}, nil, false)
	require.True(t, res.Allowed)
	assert.Equal(t, []string{"good"}, grantingNames(res.GrantingPolicies))
	sets := cbp.mcpRulesForPath("mcp/x")
	require.Len(t, sets, 1)
	assert.Equal(t, "good-mcp", sets[0].SourcePolicy)

	// A prefetched policy without parsed paths is parsed from its body, which
	// names itself "evil"; the caller's name still wins.
	prefetched := &Policy{
		Name:      "good-prefetched",
		Type:      PolicyTypeCBP,
		Raw:       "name = \"evil\"\npath \"secret/y\" { capabilities = [\"read\"] }",
		namespace: namespace.RootNamespace,
	}
	cbp, err = ps.CBP(ctx, map[string][]string{}, prefetched)
	require.NoError(t, err)
	res = cbp.AllowOperation(ctx, &logical.Request{Operation: logical.ReadOperation, Path: "secret/y"}, nil, false)
	require.True(t, res.Allowed)
	assert.Equal(t, []string{"good-prefetched"}, grantingNames(res.GrantingPolicies))
}
