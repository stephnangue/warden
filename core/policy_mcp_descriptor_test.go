// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/logical"
)

// Multi-call batch: a denied second call short-circuits the entire
// batch decision. Pins the single-fail-all-fail semantic.
func TestEvaluateMCPDescriptor_BatchOneDeniedFailsAll(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/list", "tools/call"},
		AllowedTools:   []string{"search_repos"},
	}}
	desc := &logical.MCPRequestDescriptor{
		Calls: []logical.MCPCall{
			{Method: "tools/list", BatchIndex: 0},
			{Method: "tools/call", Name: "delete_repo", BatchIndex: 1},
		},
	}
	d := evaluateMCPDescriptor(sets, desc, nil, nil, time.Time{})
	if d == nil || d.Decision != "deny" {
		t.Fatalf("decision = %+v, want deny", d)
	}
	if d.Name != "delete_repo" {
		t.Errorf("denied call's Name = %q, want delete_repo (the second batch element)", d.Name)
	}
}

// Multi-call batch where every call passes the gates returns the
// last allow decision. Pins the all-allow path.
func TestEvaluateMCPDescriptor_BatchAllAllowed(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/list", "tools/call"},
		AllowedTools:   []string{"search_repos"},
	}}
	desc := &logical.MCPRequestDescriptor{
		Calls: []logical.MCPCall{
			{Method: "tools/list", BatchIndex: 0},
			{Method: "tools/call", Name: "search_repos", BatchIndex: 1},
		},
	}
	d := evaluateMCPDescriptor(sets, desc, nil, nil, time.Time{})
	if d == nil || d.Decision != "allow" {
		t.Fatalf("decision = %+v, want allow", d)
	}
}

// Empty descriptor (zero calls) returns nil — the caller is
// responsible for denying when an mcp{} block is in scope but no body
// was parseable. decideMCP handles that in the evaluator wrapper.
func TestEvaluateMCPDescriptor_NoCallsReturnsNil(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/list"},
	}}
	if d := evaluateMCPDescriptor(sets, nil, nil, nil, time.Time{}); d != nil {
		t.Errorf("nil descriptor: decision = %+v, want nil", d)
	}
	if d := evaluateMCPDescriptor(sets, &logical.MCPRequestDescriptor{}, nil, nil, time.Time{}); d != nil {
		t.Errorf("empty Calls: decision = %+v, want nil", d)
	}
}

