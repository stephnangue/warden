// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
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
	p := testParsePolicy(t, `path "secret/x" { capabilities = ["read"] condition = "token.metadata.env == 'prod'" }`)
	cbp, err := NewCBP(ctx, []*Policy{p})
	require.NoError(t, err)

	req := &logical.Request{Operation: logical.ReadOperation, Path: "secret/x"}
	prod := &logical.TokenEntry{Metadata: map[string]string{"env": "prod"}}
	dev := &logical.TokenEntry{Metadata: map[string]string{"env": "dev"}}

	assert.True(t, cbp.AllowOperation(ctx, req, prod, false).Allowed)
	assert.False(t, cbp.AllowOperation(ctx, req, dev, false).Allowed)
}

// TestCBP_CompiledConditionCacheSharedAcrossCallers confirms a conditioned policy
// set compiles once and the cached compiled CBP is reused across callers — the
// compiled program is keyed by the policy set, not by any token identity (the
// no-templated-policies invariant).
func TestCBP_CompiledConditionCacheSharedAcrossCallers(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	p := testParsePolicy(t, `path "secret/x" { capabilities = ["read"] condition = "token.metadata.env == 'prod'" }`)
	p.Name = "cond"
	p.Type = PolicyTypeCBP
	require.NoError(t, ps.SetPolicy(ctx, p, nil))

	names := map[string][]string{namespace.RootNamespaceID: {"cond"}}
	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.Same(t, first, second, "same policy set → one cached compiled CBP, shared regardless of caller")
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
// CBPPermissions Clone Tests
// =============================================================================

func TestCBPPermissions_Clone(t *testing.T) {
	original := &CBPPermissions{
		CapabilitiesBitmap:     ReadCapabilityInt | CreateCapabilityInt,
		PaginationLimit:        100,
		ResponseKeysFilterPath: "secret/data/{{key}}",
		GrantingPoliciesMap: map[uint32][]sdklogical.PolicyInfo{
			ReadCapabilityInt: {{Name: "p1"}},
		},
	}

	cloned, err := original.Clone()
	require.NoError(t, err)

	assert.Equal(t, original.CapabilitiesBitmap, cloned.CapabilitiesBitmap)
	assert.Equal(t, original.PaginationLimit, cloned.PaginationLimit)
	assert.Equal(t, original.ResponseKeysFilterPath, cloned.ResponseKeysFilterPath)
	assert.Equal(t, original.GrantingPoliciesMap, cloned.GrantingPoliciesMap)

	// Deep copy: mutating the original's granting-policies map must not
	// affect the clone.
	original.GrantingPoliciesMap[ReadCapabilityInt] = []sdklogical.PolicyInfo{{Name: "mutated"}}
	assert.Equal(t, "p1", cloned.GrantingPoliciesMap[ReadCapabilityInt][0].Name)
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
	idx := ps.cacheKey(namespace.RootNamespace, "diverged")
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

// =============================================================================
// Compiled-CBP cache
// =============================================================================

// TestCBP_CompiledCacheHit verifies that compiling the same policy set twice
// returns the cached compiled CBP (identical pointer) instead of recompiling.
func TestCBP_CompiledCacheHit(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	p := testParsePolicy(t, `path "secret/a" { capabilities = ["read"] }`)
	p.Name = "cached-set"
	p.Type = PolicyTypeCBP
	require.NoError(t, ps.SetPolicy(ctx, p, nil))

	names := map[string][]string{namespace.RootNamespaceID: {"cached-set"}}
	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)

	assert.Same(t, first, second, "identical policy set should return the cached compiled CBP")
}

// TestCBP_CompiledCacheInvalidatesOnVersionBump verifies that editing a policy
// (which bumps its DataVersion) yields a new key, so the stale compiled CBP is
// never served.
func TestCBP_CompiledCacheInvalidatesOnVersionBump(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	p := testParsePolicy(t, `path "secret/a" { capabilities = ["read"] }`)
	p.Name = "versioned"
	p.Type = PolicyTypeCBP
	require.NoError(t, ps.SetPolicy(ctx, p, nil))

	names := map[string][]string{namespace.RootNamespaceID: {"versioned"}}
	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.Contains(t, first.Capabilities(ctx, "secret/a"), ReadCapability)

	// Edit the policy: now grants secret/b instead. SetPolicy bumps DataVersion.
	updated := testParsePolicy(t, `path "secret/b" { capabilities = ["read"] }`)
	updated.Name = "versioned"
	updated.Type = PolicyTypeCBP
	require.NoError(t, ps.SetPolicy(ctx, updated, nil))

	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.NotSame(t, first, second, "version bump must recompile")
	assert.Contains(t, second.Capabilities(ctx, "secret/b"), ReadCapability)
	assert.NotContains(t, second.Capabilities(ctx, "secret/a"), ReadCapability)
}

// TestCBP_CompiledCacheExpiresWithPath verifies that a per-path expiration
// bounds the cached compiled CBP: once it elapses the entry is recompiled and
// the expired path is dropped.
func TestCBP_CompiledCacheExpiresWithPath(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	exp := time.Now().Add(50 * time.Millisecond)
	p := &Policy{
		Name:      "expiring",
		Type:      PolicyTypeCBP,
		namespace: namespace.RootNamespace,
		Paths: []*PathRules{{
			Path:         "secret/temp",
			Capabilities: []string{ReadCapability},
			Permissions:  &CBPPermissions{CapabilitiesBitmap: ReadCapabilityInt},
			Expiration:   exp,
		}},
	}
	idx := ps.cacheKey(namespace.RootNamespace, "expiring")
	ps.tokenPoliciesLRU.Add(idx, p)

	names := map[string][]string{namespace.RootNamespaceID: {"expiring"}}
	first, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.Contains(t, first.Capabilities(ctx, "secret/temp"), ReadCapability)

	// The cached entry must carry a time bound derived from the path expiration.
	entry, ok := ps.compiledCBPLRU.Get(compiledCBPCacheKey([]*Policy{p}))
	require.True(t, ok)
	assert.False(t, entry.validUntil.IsZero(), "entry should carry a validUntil bound")

	// After the path expires, the entry is recompiled and the path is gone.
	time.Sleep(80 * time.Millisecond)
	second, err := ps.CBP(ctx, names)
	require.NoError(t, err)
	assert.NotSame(t, first, second, "expired entry must be recompiled")
	assert.NotContains(t, second.Capabilities(ctx, "secret/temp"), ReadCapability,
		"expired path must be dropped after recompile")
}

// TestCBP_CompiledCacheBypassedWithAdditionalPolicies verifies that prefetched
// policies bypass the compiled cache entirely (no sharing, no caching).
func TestCBP_CompiledCacheBypassedWithAdditionalPolicies(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	extra := &Policy{
		Name:      "prefetched",
		Type:      PolicyTypeCBP,
		Raw:       `path "secret/extra" { capabilities = ["read"] }`,
		namespace: namespace.RootNamespace,
	}

	first, err := ps.CBP(ctx, map[string][]string{}, extra)
	require.NoError(t, err)
	second, err := ps.CBP(ctx, map[string][]string{}, extra)
	require.NoError(t, err)

	assert.NotSame(t, first, second, "additional policies must bypass the compiled cache")
	assert.Equal(t, 0, ps.compiledCBPLRU.Len(), "nothing should be cached when additional policies are present")
}

// TestCBP_CompiledCacheConcurrent exercises concurrent CBP() compilation and
// evaluation of a shared cached CBP under the race detector.
func TestCBP_CompiledCacheConcurrent(t *testing.T) {
	core := createTestCore(t)
	ps := core.policyStore
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	p := testParsePolicy(t, `
		path "secret/a" { capabilities = ["read", "list"] }
		path "secret/b/*" { capabilities = ["read"] }
	`)
	p.Name = "concurrent"
	p.Type = PolicyTypeCBP
	require.NoError(t, ps.SetPolicy(ctx, p, nil))

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
