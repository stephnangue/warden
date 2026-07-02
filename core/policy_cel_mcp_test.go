// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

// mcpReq builds a streaming MCP request from a JSON-RPC body and runs the
// production extractor, leaving req.MCPDescriptor populated.
func mcpReq(t *testing.T, body string) *logical.Request {
	t.Helper()
	req := buildE2ERequest(t, body)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})
	return req
}

func mcpAmountCapPolicy(t *testing.T) *CBP {
	t.Helper()
	return mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["create_payment"]
    condition       = "call.args.amount <= 1500"
  }
}`)
}

func TestMCPCond_NumericAllowDeny(t *testing.T) {
	cbp := mcpAmountCapPolicy(t)

	allow := mcpReq(t, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":1200}},"id":1}`)
	res := cbp.AllowOperation(testContext(), allow, nil, false)
	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	require.NotNil(t, res.MCPDecision.Condition)
	assert.Equal(t, "allow", res.MCPDecision.Condition.Decision)

	deny := mcpReq(t, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":2000}},"id":1}`)
	res = cbp.AllowOperation(testContext(), deny, nil, false)
	assert.False(t, res.Allowed)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeCondition, res.MCPDecision.RuleType)
	require.NotNil(t, res.MCPDecision.Condition)
	assert.Equal(t, "deny", res.MCPDecision.Condition.Decision)
	assert.Contains(t, res.MCPDecision.Condition.Expression, "call.args.amount")
}

// TestMCPCond_TokenNamespace confirms an mcp{} condition can read the token
// namespace (threaded via the TokenEntry), not just call.*.
func TestMCPCond_TokenNamespace(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["create_payment"]
    condition       = "token.metadata.env == 'prod'"
  }
}`)
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":1}},"id":1}`

	prod := cbp.AllowOperation(testContext(), mcpReq(t, body), &logical.TokenEntry{Metadata: map[string]string{"env": "prod"}}, false)
	assert.True(t, prod.Allowed)

	dev := cbp.AllowOperation(testContext(), mcpReq(t, body), &logical.TokenEntry{Metadata: map[string]string{"env": "dev"}}, false)
	assert.False(t, dev.Allowed)
	assert.Equal(t, mcpRuleTypeCondition, dev.MCPDecision.RuleType)
}

// TestMCPCond_BatchSingleFailAllFail confirms a batch is denied when any one
// call fails the condition, with BatchIndex stamping the offending call.
func TestMCPCond_BatchSingleFailAllFail(t *testing.T) {
	cbp := mcpAmountCapPolicy(t)
	req := mcpReq(t, `[
		{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":100}},"id":1},
		{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":9000}},"id":2}
	]`)
	res := cbp.AllowOperation(testContext(), req, nil, false)
	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeCondition, res.MCPDecision.RuleType)
	require.NotNil(t, res.MCPDecision.BatchIndex)
	assert.Equal(t, 1, *res.MCPDecision.BatchIndex, "second call (index 1) is the one over cap")
}

// TestMCPCond_TypeMismatchFailsClosed confirms a non-numeric argument against a
// numeric comparison denies (fail-closed) with a sanitized error category.
func TestMCPCond_TypeMismatchFailsClosed(t *testing.T) {
	cbp := mcpAmountCapPolicy(t)
	req := mcpReq(t, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":"2000"}},"id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)
	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeConditionError, res.MCPDecision.RuleType)
	require.NotNil(t, res.MCPDecision.Condition)
	assert.Equal(t, "deny", res.MCPDecision.Condition.Decision)
	assert.NotEmpty(t, res.MCPDecision.Condition.ErrorKind)
}

// TestMCPCond_MissingArgFailsClosed confirms an absent argument denies.
func TestMCPCond_MissingArgFailsClosed(t *testing.T) {
	cbp := mcpAmountCapPolicy(t)
	req := mcpReq(t, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{}},"id":1}`)
	res := cbp.AllowOperation(testContext(), req, nil, false)
	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeConditionError, res.MCPDecision.RuleType)
}

// TestMCPCond_AppliesToEveryMethodInSet locks an important semantic: a set's
// condition applies to EVERY method the set governs, not just tools/call. A
// condition that reads call.args therefore fail-closed-denies an argument-less
// method (e.g. tools/list) the same set allows. Authors must scope with
// call.method (e.g. `call.method != "tools/call" || call.args.amount <= 1500`).
func TestMCPCond_AppliesToEveryMethodInSet(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["create_payment"]
    condition       = "call.args.amount <= 1500"
  }
}`)
	// tools/list carries no args -> the args-referencing condition errors ->
	// fail-closed deny (NOT a silent allow).
	list := mcpReq(t, `{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	res := cbp.AllowOperation(testContext(), list, nil, false)
	assert.False(t, res.Allowed, "set-wide condition denies the argument-less method")
	assert.Equal(t, mcpRuleTypeConditionError, res.MCPDecision.RuleType)

	// A properly scoped condition lets tools/list through.
	scoped := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["create_payment"]
    condition       = "call.method != 'tools/call' || call.args.amount <= 1500"
  }
}`)
	list2 := mcpReq(t, `{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	assert.True(t, scoped.AllowOperation(testContext(), list2, nil, false).Allowed, "scoped condition admits tools/list")
}

// Benchmarks reuse one extracted request across iterations (the descriptor is
// read-only during evaluation), isolating the per-call decide cost.

func benchMCP(b *testing.B, policy, body string, te *logical.TokenEntry) {
	b.Helper()
	cbp := mustCBP(b, policy)
	req := buildE2ERequest(b, body)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})
	ctx := testContext()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cbp.AllowOperation(ctx, req, te, false)
	}
}

const benchMCPNoCond = `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp { 
    allowed_methods = ["tools/call"] 
	allowed_tools   = ["create_payment"] 
  }
}`

const benchMCPWithCond = `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["create_payment"]
    condition       = "call.args.amount <= 1500"
  }
}`

const benchMCPCall = `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":1200}},"id":1}`

const benchMCPBatch = `[
	{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":100}},"id":1},
	{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":200}},"id":2},
	{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_payment","arguments":{"amount":300}},"id":3}
]`

func BenchmarkMCPDecide_NoCondition(b *testing.B)   { benchMCP(b, benchMCPNoCond, benchMCPCall, nil) }
func BenchmarkMCPDecide_WithCondition(b *testing.B) { benchMCP(b, benchMCPWithCond, benchMCPCall, nil) }
func BenchmarkMCPDecide_Batch3_NoCondition(b *testing.B) {
	benchMCP(b, benchMCPNoCond, benchMCPBatch, nil)
}
func BenchmarkMCPDecide_Batch3_WithCondition(b *testing.B) {
	benchMCP(b, benchMCPWithCond, benchMCPBatch, nil)
}
