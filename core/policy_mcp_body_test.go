// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Production switch: a request reaches AllowOperation with no
// descriptor attached (e.g. the routed backend doesn't implement
// MCPPolicyEnforced or declined this request) and the matched policy
// has an mcp{} block in scope. Body-authoritative enforcement fails
// CLOSED — the decision is deny with rule_type missing_body.
func TestDecideMCP_NilDescriptorDeniesMissingBody(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/list"},
	}}
	req := &logical.Request{} // no MCPDescriptor
	d := decideMCP(sets, req, nil, time.Time{})
	require.NotNil(t, d)
	assert.Equal(t, "deny", d.Decision)
	assert.Equal(t, mcpRuleTypeMissingBody, d.RuleType)
}

// Production switch: descriptor.ParseErr maps 1:1 to MCPDecision.
// RuleType. The error Msg never propagates onto the decision (only the
// Kind does) so adversary-controlled body bytes don't leak into audit.
func TestDecideMCP_ParseErrMapsByKind(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/list"},
	}}
	cases := []struct {
		kind     string
		ruleType string
	}{
		{logical.MCPParseKindMalformedJSONRPC, mcpRuleTypeMalformedJSONRPC},
		{logical.MCPParseKindDuplicateKey, mcpRuleTypeDuplicateKey},
		{logical.MCPParseKindOversizedBody, mcpRuleTypeOversizedBody},
		{logical.MCPParseKindBatchEmpty, mcpRuleTypeBatchEmpty},
		{logical.MCPParseKindMalformedParams, mcpRuleTypeMalformedParams},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			req := &logical.Request{
				MCPDescriptor: &logical.MCPRequestDescriptor{
					ParseErr: &logical.MCPParseError{
						Kind: tc.kind,
						Msg:  "adversary-controlled detail SHOULD NOT LEAK",
					},
				},
			}
			d := decideMCP(sets, req, nil, time.Time{})
			require.NotNil(t, d)
			assert.Equal(t, "deny", d.Decision)
			assert.Equal(t, tc.ruleType, d.RuleType)
			// ParseErr.Msg must not appear anywhere on the decision.
			assert.NotContains(t, d.Method, "SHOULD NOT LEAK")
			assert.NotContains(t, d.Name, "SHOULD NOT LEAK")
			assert.NotContains(t, d.MatchedRule, "SHOULD NOT LEAK")
			assert.NotContains(t, d.ParamValue, "SHOULD NOT LEAK")
		})
	}
}

// Production switch: a healthy descriptor + matching policy = allow.
// Pins the end-to-end happy path from the body source.
func TestDecideMCP_DescriptorMatcherAllows(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/call"},
		AllowedTools:   []string{"search_repos"},
	}}
	req := &logical.Request{
		MCPDescriptor: &logical.MCPRequestDescriptor{
			Calls: []logical.MCPCall{{
				Method: "tools/call",
				Name:   "search_repos",
			}},
		},
	}
	d := decideMCP(sets, req, nil, time.Time{})
	require.NotNil(t, d)
	assert.Equal(t, "allow", d.Decision)
}

// The empty-but-non-nil descriptor is the deliberate sentinel an
// MCP-aware backend installs via extractMCPDescriptor when
// ShouldEnforceMCPPolicy declines for a specific request (typically a
// non-POST verb on a multi-method MCP endpoint). decideMCP must
// return nil (skip evaluation) for this shape so the cap-level check
// can decide — the mcp{} block is body-authoritative and can't
// meaningfully gate a verb the backend declared body-less.
//
// This is what lets MCP Streamable HTTP's GET (notification SSE
// stream) and DELETE (session terminate) share the same URL as the
// POST that mcp{} gates without the multi-method path tripping
// missing_body. The nil-descriptor case (genuine misconfig: mcp{}
// bound to a non-MCP backend) still fails closed, covered by
// TestDecideMCP_DescriptorMissingFailsClosed.
func TestDecideMCP_EmptyDescriptorSkipsEvaluation(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/list"},
	}}
	req := &logical.Request{
		MCPDescriptor: &logical.MCPRequestDescriptor{
			// Calls nil, ParseErr nil — the per-request opt-out sentinel.
		},
	}
	d := decideMCP(sets, req, nil, time.Time{})
	assert.Nil(t, d, "decideMCP must return nil for the per-request opt-out sentinel so the cap-level check decides")
}

// Empty sets — no mcp{} block in scope — returns nil. The
// AllowOperation caller treats nil as "no MCP enforcement applied"
// and continues to parameter validation.
func TestDecideMCP_EmptySetsReturnNil(t *testing.T) {
	req := &logical.Request{
		MCPDescriptor: &logical.MCPRequestDescriptor{
			Calls: []logical.MCPCall{{Method: "tools/list"}},
		},
	}
	if d := decideMCP(nil, req, nil, time.Time{}); d != nil {
		t.Errorf("decision = %+v, want nil for empty sets", d)
	}
	if d := decideMCP([]*CBPMCPRules{}, req, nil, time.Time{}); d != nil {
		t.Errorf("decision = %+v, want nil for empty sets slice", d)
	}
}

// Batch deny stamps BatchIndex on the deciding call. Pins the
// informational-index contract from the plan.
func TestEvaluateMCPDescriptor_BatchDenyStampsBatchIndex(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/list", "tools/call"},
		AllowedTools:   []string{"search_repos"},
	}}
	desc := &logical.MCPRequestDescriptor{
		Calls: []logical.MCPCall{
			{Method: "tools/list", BatchIndex: 0},
			{Method: "tools/list", BatchIndex: 1},
			{Method: "tools/call", Name: "delete_repo", BatchIndex: 2},
		},
	}
	d := evaluateMCPDescriptor(sets, desc, nil, nil, time.Time{})
	require.NotNil(t, d)
	require.Equal(t, "deny", d.Decision)
	require.NotNil(t, d.BatchIndex, "BatchIndex should be stamped for batch denies")
	assert.Equal(t, 2, *d.BatchIndex)
}

// Single-message body: BatchIndex must stay nil. The plan reserves
// the field for batch denies only.
func TestEvaluateMCPDescriptor_SingleCallLeavesBatchIndexNil(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/call"},
	}}
	desc := &logical.MCPRequestDescriptor{
		Calls: []logical.MCPCall{
			{Method: "tools/call", Name: "delete_repo"},
		},
	}
	d := evaluateMCPDescriptor(sets, desc, nil, nil, time.Time{})
	require.NotNil(t, d)
	if d.BatchIndex != nil {
		t.Errorf("BatchIndex = %v, want nil for single-call descriptor", *d.BatchIndex)
	}
}

// sanitizeMCPDecision strips ASCII control characters from every
// string field. Adversary-controlled body bytes (Method, Name,
// ParamValue extracted from JSON strings) must not propagate CTLs
// into audit logs or the WWW-Authenticate quoted-string.
func TestSanitizeMCPDecision_StripsCTLs(t *testing.T) {
	d := &logical.MCPDecision{
		Method:      "tools/call\x01injected",
		Name:        "delete_repo\nLog inject",
		MatchedRule: "delete_*\rextra",
		ParamName:   "path\x00",
		ParamValue:  "/etc/shadow\x7f",
	}
	sanitizeMCPDecision(d)
	assert.Equal(t, "tools/callinjected", d.Method)
	assert.Equal(t, "delete_repoLog inject", d.Name)
	assert.Equal(t, "delete_*extra", d.MatchedRule)
	assert.Equal(t, "path", d.ParamName)
	assert.Equal(t, "/etc/shadow", d.ParamValue)
}

// nil decision is a no-op. Defensive against the empty-sets / nil-
// descriptor branches where decideMCP can produce a nil before
// stamping.
func TestSanitizeMCPDecision_NilSafe(t *testing.T) {
	// Should not panic.
	sanitizeMCPDecision(nil)
}

// Decision routed through decideMCP has CTL-stripped strings even
// when the source descriptor carries adversarial bytes. Pins the
// boundary sanitiser as the single application point. The matcher
// itself sees the raw bytes — the policy gate fires on the
// CTL-prefixed name because matchMCPGlob's prefix match still
// matches "delete_*" against "delete_repo\x01injected" — but the
// decision returned by decideMCP has the CTL stripped before audit
// sees it.
func TestDecideMCP_SanitizesDecisionBoundary(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/call"},
		DeniedTools:    []string{"delete_*"},
	}}
	req := &logical.Request{
		MCPDescriptor: &logical.MCPRequestDescriptor{
			Calls: []logical.MCPCall{{
				Method: "tools/call",
				Name:   "delete_repo\x01injected",
			}},
		},
	}
	d := decideMCP(sets, req, nil, time.Time{})
	require.NotNil(t, d)
	assert.Equal(t, "deny", d.Decision)
	assert.Equal(t, mcpRuleTypeDeniedTools, d.RuleType)
	assert.NotContains(t, d.Name, "\x01")
	assert.Equal(t, "delete_repoinjected", d.Name)
}

// mcpDenyRank: structural-failure rule_types outrank explicit-deny
// matches so that multi-set denies surface the more informative
// reason. Today the structural codes are produced by decideMCP
// BEFORE evaluateMCPDescriptor runs, but the ranking matters for
// future code paths.
func TestMCPDenyRank_StructuralFailuresOutrankExplicitDeny(t *testing.T) {
	cases := []struct {
		ruleType string
		want     int
	}{
		{mcpRuleTypeMissingBody, 4},
		{mcpRuleTypeMalformedJSONRPC, 4},
		{mcpRuleTypeDuplicateKey, 4},
		{mcpRuleTypeOversizedBody, 4},
		{mcpRuleTypeBatchEmpty, 4},
		{mcpRuleTypeMalformedParams, 4},
		{mcpRuleTypeDeniedMethods, 3},
		{mcpRuleTypeDeniedTools, 3},
		{mcpRuleTypeDeniedResources, 3},
		{mcpRuleTypeDeniedPrompts, 3},
		{mcpRuleTypeDeniedParams, 3},
		{mcpRuleTypeAllowedMethods, 2},
		{mcpRuleTypeAllowedTools, 2},
		{mcpRuleTypeAllowedResources, 2},
		{mcpRuleTypeAllowedPrompts, 2},
		{mcpRuleTypeAllowedParams, 2},
		{mcpRuleTypeMissingMethod, 1},
		{"unknown", 0},
	}
	for _, tc := range cases {
		t.Run(tc.ruleType, func(t *testing.T) {
			assert.Equal(t, tc.want, mcpDenyRank(tc.ruleType))
		})
	}
}
