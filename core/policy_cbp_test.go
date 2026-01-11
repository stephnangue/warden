// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a context with root namespace
func testContext() context.Context {
	return namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
}

// Helper function to parse a policy for testing
func testParsePolicy(t *testing.T, rules string) *Policy {
	t.Helper()
	policy, err := ParseCBPPolicy(namespace.RootNamespace, rules)
	require.NoError(t, err)
	return policy
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

			result := cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// Different path should not be allowed
	req.Path = "secret/data/otherkey"
	result = cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// Longer path should not match
	req.Path = "secret/data/specific/extra"
	result = cbp.AllowOperation(ctx, req, false)
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
			result := cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// kv/* should have read and create
	req.Path = "kv/data"
	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, false)
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
			result := cbp.AllowOperation(ctx, req, false)
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
		{"secret/app1/data", false},             // Missing last segment
		{"secret/app1/metadata/key1", false},    // Wrong middle segment
		{"secret/app1/data/key1/extra", false},  // Extra segment
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req := &logical.Request{
				Path:      tc.path,
				Operation: logical.ReadOperation,
			}
			result := cbp.AllowOperation(ctx, req, false)
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
			result := cbp.AllowOperation(ctx, req, false)
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
			result := cbp.AllowOperation(ctx, req, false)
			assert.True(t, result.Allowed, "operation: %s", op)
		})
	}

	// Check sudo privilege
	req := &logical.Request{
		Path:      "test/key",
		Operation: logical.ReadOperation,
	}
	result := cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// writeonly path
	req.Path = "writeonly/key"
	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.ReadOperation
	result = cbp.AllowOperation(ctx, req, false)
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
			result := cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	req.Operation = logical.UpdateOperation
	result = cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// But not delete
	req.Operation = logical.DeleteOperation
	result = cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	req.Operation = logical.CreateOperation
	result = cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)
}

// =============================================================================
// Parameter Tests - Allowed Parameters
// =============================================================================

func TestCBP_AllowedParameters(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/*" {
			capabilities = ["create", "update"]
			allowed_parameters = {
				"key1" = []
				"key2" = ["value1", "value2"]
			}
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Empty allowed values means any value is allowed
	req := &logical.Request{
		Path:      "secret/data/test",
		Operation: logical.CreateOperation,
		Data: map[string]interface{}{
			"key1": "any-value",
		},
	}
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// Specific allowed value
	req.Data = map[string]interface{}{
		"key2": "value1",
	}
	result = cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// Value not in allowed list
	req.Data = map[string]interface{}{
		"key2": "value3",
	}
	result = cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// Parameter not in allowed list
	req.Data = map[string]interface{}{
		"key3": "value",
	}
	result = cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)
}

func TestCBP_AllowedParametersWildcard(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/*" {
			capabilities = ["create"]
			allowed_parameters = {
				"*" = []
			}
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Any parameter should be allowed
	req := &logical.Request{
		Path:      "secret/data/test",
		Operation: logical.CreateOperation,
		Data: map[string]interface{}{
			"any_key": "any_value",
			"another": "value",
		},
	}
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)
}

// =============================================================================
// Parameter Tests - Denied Parameters
// =============================================================================

func TestCBP_DeniedParameters(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/*" {
			capabilities = ["create", "update"]
			denied_parameters = {
				"password" = []
				"secret_key" = ["forbidden_value"]
			}
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Denied parameter with any value
	req := &logical.Request{
		Path:      "secret/data/test",
		Operation: logical.CreateOperation,
		Data: map[string]interface{}{
			"password": "any-password",
		},
	}
	result := cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// Denied parameter with specific value
	req.Data = map[string]interface{}{
		"secret_key": "forbidden_value",
	}
	result = cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// Denied parameter with non-forbidden value
	req.Data = map[string]interface{}{
		"secret_key": "allowed_value",
	}
	result = cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// Non-denied parameter
	req.Data = map[string]interface{}{
		"normal_key": "value",
	}
	result = cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)
}

func TestCBP_DeniedParametersWildcard(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/*" {
			capabilities = ["create"]
			denied_parameters = {
				"*" = []
			}
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// Any parameter should be denied
	req := &logical.Request{
		Path:      "secret/data/test",
		Operation: logical.CreateOperation,
		Data: map[string]interface{}{
			"any_key": "value",
		},
	}
	result := cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// No data should be allowed
	req.Data = nil
	result = cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)
}

// =============================================================================
// Parameter Tests - Required Parameters
// =============================================================================

func TestCBP_RequiredParameters(t *testing.T) {
	ctx := testContext()

	policy := testParsePolicy(t, `
		path "secret/data/*" {
			capabilities = ["create"]
			required_parameters = ["name", "type"]
		}
	`)

	cbp, err := NewCBP(ctx, []*Policy{policy})
	require.NoError(t, err)

	// All required parameters present
	req := &logical.Request{
		Path:      "secret/data/test",
		Operation: logical.CreateOperation,
		Data: map[string]interface{}{
			"name": "test",
			"type": "secret",
		},
	}
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// Missing required parameter
	req.Data = map[string]interface{}{
		"name": "test",
	}
	result = cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// No data at all
	req.Data = nil
	result = cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// List operation without trailing slash
	req.Path = "secret/data"
	result = cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// Exceeds limit
	req.Data = map[string]interface{}{
		"limit": 200,
	}
	result = cbp.AllowOperation(ctx, req, false)
	assert.False(t, result.Allowed)

	// Using "max" keyword
	req.Data = map[string]interface{}{
		"limit": "max",
	}
	result = cbp.AllowOperation(ctx, req, false)
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
			result := cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, true)
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
	result := cbp.AllowOperation(ctx, req, false)
	assert.True(t, result.Allowed)

	// Path without leading slash
	req.Path = "secret/data"
	result = cbp.AllowOperation(ctx, req, false)
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
	result := cbp.AllowOperation(ctx, req, false)
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
		CapabilitiesBitmap: ReadCapabilityInt | CreateCapabilityInt,
		AllowedParameters: map[string][]any{
			"key1": {"value1", "value2"},
		},
		DeniedParameters: map[string][]any{
			"password": {},
		},
		RequiredParameters: []string{"name", "type"},
		PaginationLimit:    100,
	}

	cloned, err := original.Clone()
	require.NoError(t, err)

	// Verify values are copied
	assert.Equal(t, original.CapabilitiesBitmap, cloned.CapabilitiesBitmap)
	assert.Equal(t, original.PaginationLimit, cloned.PaginationLimit)
	assert.Equal(t, original.RequiredParameters, cloned.RequiredParameters)

	// Verify deep copy of maps
	assert.Equal(t, original.AllowedParameters, cloned.AllowedParameters)
	assert.Equal(t, original.DeniedParameters, cloned.DeniedParameters)

	// Modify original and verify clone is not affected
	original.AllowedParameters["key1"] = []any{"modified"}
	assert.NotEqual(t, original.AllowedParameters["key1"], cloned.AllowedParameters["key1"])
}

func TestCBPPermissions_CloneNilMaps(t *testing.T) {
	original := &CBPPermissions{
		CapabilitiesBitmap: ReadCapabilityInt,
		RequiredParameters: []string{},
	}

	cloned, err := original.Clone()
	require.NoError(t, err)

	assert.Nil(t, cloned.AllowedParameters)
	assert.Nil(t, cloned.DeniedParameters)
}

func TestCBPPermissions_CloneEmptyMaps(t *testing.T) {
	original := &CBPPermissions{
		CapabilitiesBitmap: ReadCapabilityInt,
		AllowedParameters:  map[string][]any{},
		DeniedParameters:   map[string][]any{},
		RequiredParameters: []string{},
	}

	cloned, err := original.Clone()
	require.NoError(t, err)

	assert.NotNil(t, cloned.AllowedParameters)
	assert.NotNil(t, cloned.DeniedParameters)
	assert.Len(t, cloned.AllowedParameters, 0)
	assert.Len(t, cloned.DeniedParameters, 0)
}
