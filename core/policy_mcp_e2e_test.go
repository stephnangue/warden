// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Provider-agnostic e2e integration tests.
//
// These tests exercise the FULL production pipeline:
//
//   HTTP body → c.extractMCPDescriptor → req.MCPDescriptor →
//   cbp.AllowOperation → decideMCP → MCPDecision.
//
// Unit tests elsewhere cover each layer in isolation — the extractor
// with a stub matcher, the matcher with a stub descriptor. This file
// pins the seam where they meet (the production code path) and
// proves the marker-interface contract is provider-agnostic by
// driving the same scenarios through two unrelated mock backends.
// =============================================================================

// mcpMockBackend is a minimal logical.Backend that implements
// logical.MCPPolicyEnforced. Used to prove that any backend opting
// into the marker interface gets the same enforcement behaviour as
// the mcp provider — no special-casing in the policy layer.
type mcpMockBackend struct {
	logical.Backend
	enforce bool
	cap     int64
}

func (b *mcpMockBackend) ShouldEnforceMCPPolicy(_ *logical.Request) (bool, int64) {
	if !b.enforce {
		return false, 0
	}
	return true, b.cap
}

// mcpMockBackendAlt is a SECOND mock backend type — same contract,
// different struct. Used in TestMCPE2E_ProviderAgnostic to prove the
// policy layer cannot tell them apart.
type mcpMockBackendAlt struct {
	logical.Backend
	enforce bool
	cap     int64
}

func (b *mcpMockBackendAlt) ShouldEnforceMCPPolicy(_ *logical.Request) (bool, int64) {
	return b.enforce, b.cap
}

// nonMCPBackend deliberately does NOT implement MCPPolicyEnforced.
// Used to prove the extractor fails the type assertion and leaves the
// descriptor nil, so decideMCP denies missing_body when mcp{} is in
// scope.
type nonMCPBackend struct {
	logical.Backend
}

// buildE2ERequest constructs a logical.Request shaped like real
// streaming MCP traffic — POST, application/json, body in
// HTTPRequest.Body. Exercises the same headers and shape the
// production handler would see.
func buildE2ERequest(t testing.TB, body string) *logical.Request {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/mcp/gateway/", strings.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	return &logical.Request{
		Path:        "mcp/gateway/",
		Operation:   logical.UpdateOperation,
		HTTPRequest: httpReq,
	}
}

// runExtract drives the production extractor against the supplied
// backend. Returns a fresh *Core every call so tests are independent.
func runExtract(req *logical.Request, backend logical.Backend) {
	c := &Core{}
	c.extractMCPDescriptor(context.Background(), req, backend)
}

// =============================================================================
// Positive paths — extractor + decideMCP allow correctly.
// =============================================================================

func TestMCPE2E_ToolsCallAllow(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    allowed_tools   = ["search_repos"]
  }
}
`)
	req := buildE2ERequest(t, `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "search_repos"},
		"id":      1
	}`)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Equal(t, "tools/call", res.MCPDecision.Method)
	assert.Equal(t, "search_repos", res.MCPDecision.Name)
}

func TestMCPE2E_BatchAllAllowed(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    allowed_tools   = ["search_repos"]
  }
}
`)
	req := buildE2ERequest(t, `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "search_repos"}, "id": 2},
		{"jsonrpc": "2.0", "method": "tools/list", "id": 3}
	]`)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Equal(t, "allow", res.MCPDecision.Decision)
	assert.Nil(t, res.MCPDecision.BatchIndex,
		"all-allowed batch leaves BatchIndex nil")
}

// Body byte-identity: after the extractor reads and restores the
// body, downstream readers (the proxy) get the exact bytes that came
// off the wire. Load-bearing for the streaming-branch restoration
// claim — if this regresses, the upstream MCP server would see a
// truncated or different body than the client sent, which is a
// silent correctness bug.
func TestMCPE2E_BodyByteIdentityAfterExtraction(t *testing.T) {
	original := `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "search_repos", "arguments": {"q": "warden mcp"}},
		"id":      42
	}`
	req := buildE2ERequest(t, original)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	require.NotNil(t, req.MCPDescriptor)
	require.Nil(t, req.MCPDescriptor.ParseErr)
	require.NotNil(t, req.HTTPRequest.Body, "body must be restored, not left consumed")

	got, err := io.ReadAll(req.HTTPRequest.Body)
	require.NoError(t, err)
	assert.Equal(t, original, string(got),
		"restored body must be byte-identical to wire bytes")
}

// =============================================================================
// Gate denies — each gate type fires correctly through the production
// pipeline.
// =============================================================================

func TestMCPE2E_DeniedToolFiresCorrectly(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    denied_tools    = ["delete_*"]
  }
}
`)
	req := buildE2ERequest(t, `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repo"},
		"id":      1
	}`)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision)
	assert.Equal(t, "deny", res.MCPDecision.Decision)
	assert.Equal(t, mcpRuleTypeDeniedTools, res.MCPDecision.RuleType)
	assert.Equal(t, "delete_*", res.MCPDecision.MatchedRule)
}

func TestMCPE2E_BatchDenyStampsBatchIndex(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list", "tools/call"]
    denied_tools    = ["delete_*"]
  }
}
`)
	req := buildE2ERequest(t, `[
		{"jsonrpc": "2.0", "method": "tools/list", "id": 1},
		{"jsonrpc": "2.0", "method": "tools/list", "id": 2},
		{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_repo"}, "id": 3}
	]`)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	require.NotNil(t, res.MCPDecision.BatchIndex)
	assert.Equal(t, 2, *res.MCPDecision.BatchIndex)
}

// =============================================================================
// Structural failures — extractor produces a ParseErr that decideMCP
// maps 1:1 to MCPDecision.RuleType.
// =============================================================================

func TestMCPE2E_MalformedBody_DeniesMalformedJSONRPC(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	req := buildE2ERequest(t, `{ not json`)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeMalformedJSONRPC, res.MCPDecision.RuleType)
}

func TestMCPE2E_DuplicateKey_DeniesDuplicateKey(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	req := buildE2ERequest(t, `{
		"jsonrpc": "2.0",
		"method":  "tools/list",
		"method":  "tools/call",
		"id":      1
	}`)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeDuplicateKey, res.MCPDecision.RuleType)
}

func TestMCPE2E_OversizedBody_DeniesOversizedBody(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
  }
}
`)
	const cap = int64(64)
	// Cap at 64 bytes; body is well over that.
	body := `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "x", "arguments": {"big": "` + strings.Repeat("A", 256) + `"}},
		"id":      1
	}`
	req := buildE2ERequest(t, body)
	runExtract(req, &mcpMockBackend{enforce: true, cap: cap})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeOversizedBody, res.MCPDecision.RuleType)

	// Body must still be restored even on the structural-deny path —
	// the extractor wraps NopCloser(bytes.NewReader) BEFORE returning
	// the oversize. A future refactor that moved the restoration after
	// the oversize check would silently consume the body and break
	// downstream readers; this assertion pins the ordering.
	require.NotNil(t, req.HTTPRequest.Body)
	restored, err := io.ReadAll(req.HTTPRequest.Body)
	require.NoError(t, err)
	assert.Equal(t, int(cap+1), len(restored),
		"restored body should hold the cap+1 bytes that triggered the oversize check")
}

// tools/call body where params.name is an object instead of a string.
// The strict parser bails with malformed_params; decideMCP maps to
// the same RuleType. Pins the symmetry with malformed_jsonrpc /
// duplicate_key / batch_empty through the production pipeline.
func TestMCPE2E_MalformedParams_DeniesMalformedParams(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
  }
}
`)
	req := buildE2ERequest(t, `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": {"nested": "object"}},
		"id":      1
	}`)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeMalformedParams, res.MCPDecision.RuleType)
}


func TestMCPE2E_EmptyBatch_DeniesBatchEmpty(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	req := buildE2ERequest(t, `[]`)
	runExtract(req, &mcpMockBackend{enforce: true, cap: 1 << 20})

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeBatchEmpty, res.MCPDecision.RuleType)
}

// =============================================================================
// Opt-out paths — the backend declines per-request or doesn't
// implement the marker at all. With mcp{} in scope this is a deny
// (defence in depth); without mcp{} this is a clean passthrough.
// =============================================================================

// Backend opts out per-request (ShouldEnforceMCPPolicy returns false)
// and mcp{} is in scope → request passes through. This is the canonical
// MCP Streamable HTTP shape: GET on the same /gateway URL as the POST
// that mcp{} gates. The body-authoritative block can't meaningfully
// apply to a verb the backend declared body-less, so decideMCP skips
// evaluation and the cap-level check decides. Without this behavior,
// every MCP-spec-compliant client that opens an SSE notification
// stream would hit missing_body.
func TestMCPE2E_PerRequestOptOut_WithMCPBlock_PassesThrough(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	req := buildE2ERequest(t, `{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	runExtract(req, &mcpMockBackend{enforce: false, cap: 0})

	require.NotNil(t, req.MCPDescriptor,
		"opt-out installs the empty sentinel so decideMCP can distinguish per-request opt-out from misconfig")
	require.Nil(t, req.MCPDescriptor.Calls,
		"sentinel descriptor must have Calls nil")
	require.Nil(t, req.MCPDescriptor.ParseErr,
		"sentinel descriptor must have ParseErr nil")

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, res.MCPDecision,
		"empty sentinel skips mcp{} evaluation; cap-level check decides")
}

// Same opt-out, no mcp{} in scope → matcher never runs, request
// passes through cleanly. Symmetry with the mcp{}-in-scope test: the
// empty sentinel is installed either way, and decideMCP isn't even
// called because permissions.MCP is empty.
func TestMCPE2E_PerRequestOptOut_NoMCPBlock_PassesThrough(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
}
`)
	req := buildE2ERequest(t, `{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	runExtract(req, &mcpMockBackend{enforce: false, cap: 0})

	require.NotNil(t, req.MCPDescriptor,
		"opt-out installs the empty sentinel regardless of whether mcp{} is in scope")
	require.Nil(t, req.MCPDescriptor.Calls)
	require.Nil(t, req.MCPDescriptor.ParseErr)

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.True(t, res.Allowed)
	assert.Nil(t, res.MCPDecision)
}

// Backend doesn't implement MCPPolicyEnforced at all → same as
// per-request opt-out from the extractor's perspective. Pins the
// "operator bound mcp{} to a non-MCP path" misconfiguration scenario.
func TestMCPE2E_NonMCPBackend_WithMCPBlock_DeniesMissingBody(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/list"]
  }
}
`)
	req := buildE2ERequest(t, `{"jsonrpc":"2.0","method":"tools/list","id":1}`)
	runExtract(req, &nonMCPBackend{})

	require.Nil(t, req.MCPDescriptor,
		"non-MCP backend (no marker interface) leaves descriptor nil")

	res := cbp.AllowOperation(testContext(), req, nil, false)

	assert.False(t, res.Allowed)
	assert.Equal(t, mcpRuleTypeMissingBody, res.MCPDecision.RuleType)
}

// =============================================================================
// Provider-agnostic contract — the policy layer cannot tell mock
// backends apart. The marker interface is the entire contract.
// =============================================================================

// A second, structurally different mock backend (mcpMockBackendAlt)
// satisfying the same interface produces the SAME decision as the
// first mock for an identical scenario. Proves that the policy layer
// is truly provider-agnostic and that future mcp_* providers inherit
// enforcement by implementing one method.
func TestMCPE2E_ProviderAgnostic_TwoBackendsSameOutcome(t *testing.T) {
	cbp := mustCBP(t, `
path "mcp/gateway/*" {
  capabilities = ["update"]
  mcp {
    allowed_methods = ["tools/call"]
    denied_tools    = ["delete_*"]
  }
}
`)
	body := `{
		"jsonrpc": "2.0",
		"method":  "tools/call",
		"params":  {"name": "delete_repo"},
		"id":      1
	}`

	// Backend type A.
	reqA := buildE2ERequest(t, body)
	runExtract(reqA, &mcpMockBackend{enforce: true, cap: 1 << 20})
	resA := cbp.AllowOperation(testContext(), reqA, nil, false)

	// Backend type B (different struct, same interface).
	reqB := buildE2ERequest(t, body)
	runExtract(reqB, &mcpMockBackendAlt{enforce: true, cap: 1 << 20})
	resB := cbp.AllowOperation(testContext(), reqB, nil, false)

	require.NotNil(t, resA.MCPDecision)
	require.NotNil(t, resB.MCPDecision)

	// Identical decisions on every audit-bearing field.
	assert.Equal(t, resA.Allowed, resB.Allowed)
	assert.Equal(t, resA.MCPDecision.Decision, resB.MCPDecision.Decision)
	assert.Equal(t, resA.MCPDecision.RuleType, resB.MCPDecision.RuleType)
	assert.Equal(t, resA.MCPDecision.Method, resB.MCPDecision.Method)
	assert.Equal(t, resA.MCPDecision.Name, resB.MCPDecision.Name)
	assert.Equal(t, resA.MCPDecision.MatchedRule, resB.MCPDecision.MatchedRule)
}
