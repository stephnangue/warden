// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"testing"

	"github.com/stephnangue/warden/logical"
)

// Single-call descriptor with a string param matches the same way the
// header path does — pins the equivalence Phase 4 relies on when the
// production call site switches from headers to body.
func TestEvaluateMCPDescriptor_SingleCallParamString(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/call"},
		AllowedTools:   []string{"read_file"},
		AllowedParams: map[string][]string{
			"path": {"docs/*"},
		},
	}}
	desc := &logical.MCPRequestDescriptor{
		Calls: []logical.MCPCall{{
			Method: "tools/call",
			Name:   "read_file",
			MatchArgs: map[string]logical.ParamValue{
				"path": {Kind: logical.ParamString, Str: "docs/readme.md"},
			},
		}},
	}
	d := evaluateMCPDescriptor(sets, desc)
	if d == nil || d.Decision != "allow" {
		t.Fatalf("decision = %+v, want allow", d)
	}
}

// Body-extracted numeric arg renders via json.Number.String() and
// matches against the operator's string pattern. Validates the
// "numeric arguments stringify" contract from the plan.
func TestEvaluateMCPDescriptor_NumericParamMatches(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/call"},
		AllowedTools:   []string{"set_limit"},
		DeniedParams: map[string][]string{
			"count": {"42"},
		},
	}}
	desc := &logical.MCPRequestDescriptor{
		Calls: []logical.MCPCall{{
			Method: "tools/call",
			Name:   "set_limit",
			MatchArgs: map[string]logical.ParamValue{
				"count": {Kind: logical.ParamNumber, Str: "42"},
			},
		}},
	}
	d := evaluateMCPDescriptor(sets, desc)
	if d == nil || d.Decision != "deny" {
		t.Fatalf("decision = %+v, want deny", d)
	}
	if d.RuleType != mcpRuleTypeDeniedParams || d.ParamName != "count" || d.ParamValue != "42" {
		t.Errorf("decision = %+v, want denied_params count=42", d)
	}
}

// Object-typed argument values can never match a string pattern: the
// matcher treats them as missing for deny-list checks (skip) and as
// missing-required for allow-list checks (deny). Pins both halves.
func TestEvaluateMCPDescriptor_NonScalarParamTreatedAsMissing(t *testing.T) {
	t.Run("deny list skips object", func(t *testing.T) {
		sets := []*CBPMCPRules{{
			AllowedMethods: []string{"tools/call"},
			AllowedTools:   []string{"x"},
			DeniedParams: map[string][]string{
				"cfg": {"*"},
			},
		}}
		desc := &logical.MCPRequestDescriptor{
			Calls: []logical.MCPCall{{
				Method: "tools/call",
				Name:   "x",
				MatchArgs: map[string]logical.ParamValue{
					"cfg": {Kind: logical.ParamObject},
				},
			}},
		}
		d := evaluateMCPDescriptor(sets, desc)
		if d == nil || d.Decision != "allow" {
			t.Fatalf("decision = %+v, want allow (object value skipped by deny gate)", d)
		}
	})
	t.Run("allow list denies object as missing-required", func(t *testing.T) {
		sets := []*CBPMCPRules{{
			AllowedMethods: []string{"tools/call"},
			AllowedTools:   []string{"x"},
			AllowedParams: map[string][]string{
				"cfg": {"*"},
			},
		}}
		desc := &logical.MCPRequestDescriptor{
			Calls: []logical.MCPCall{{
				Method: "tools/call",
				Name:   "x",
				MatchArgs: map[string]logical.ParamValue{
					"cfg": {Kind: logical.ParamObject},
				},
			}},
		}
		d := evaluateMCPDescriptor(sets, desc)
		if d == nil || d.Decision != "deny" {
			t.Fatalf("decision = %+v, want deny (object value can't satisfy allow-list)", d)
		}
		if d.RuleType != mcpRuleTypeAllowedParams || d.ParamName != "cfg" {
			t.Errorf("decision = %+v, want allowed_params cfg", d)
		}
	})
}

// Multi-call batch: a denied second call short-circuits the entire
// batch decision. Pins the single-fail-all-fail semantic for Phase 4.
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
	d := evaluateMCPDescriptor(sets, desc)
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
	d := evaluateMCPDescriptor(sets, desc)
	if d == nil || d.Decision != "allow" {
		t.Fatalf("decision = %+v, want allow", d)
	}
}

// Empty descriptor (zero calls) returns nil — the caller is
// responsible for denying when an mcp{} block is in scope but no body
// was parseable. Phase 4 handles that in the evaluator wrapper.
func TestEvaluateMCPDescriptor_NoCallsReturnsNil(t *testing.T) {
	sets := []*CBPMCPRules{{
		AllowedMethods: []string{"tools/list"},
	}}
	if d := evaluateMCPDescriptor(sets, nil); d != nil {
		t.Errorf("nil descriptor: decision = %+v, want nil", d)
	}
	if d := evaluateMCPDescriptor(sets, &logical.MCPRequestDescriptor{}); d != nil {
		t.Errorf("empty Calls: decision = %+v, want nil", d)
	}
}

// callMatchArgString returns "" for every non-scalar kind so the
// matcher treats those uniformly as missing.
func TestCallMatchArgString(t *testing.T) {
	cases := []struct {
		name string
		pv   logical.ParamValue
		want string
	}{
		{"string", logical.ParamValue{Kind: logical.ParamString, Str: "hello"}, "hello"},
		{"number", logical.ParamValue{Kind: logical.ParamNumber, Str: "42"}, "42"},
		{"bool", logical.ParamValue{Kind: logical.ParamBool, Str: "true"}, "true"},
		{"null", logical.ParamValue{Kind: logical.ParamNull}, ""},
		{"object", logical.ParamValue{Kind: logical.ParamObject}, ""},
		{"array", logical.ParamValue{Kind: logical.ParamArray}, ""},
		{"missing", logical.ParamValue{Kind: logical.ParamMissing}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			call := &logical.MCPCall{
				MatchArgs: map[string]logical.ParamValue{"x": tc.pv},
			}
			if got := callMatchArgString(call, "x"); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
	// nil receiver / nil map / missing key — all "".
	if got := callMatchArgString(nil, "x"); got != "" {
		t.Errorf("nil call: got %q, want empty", got)
	}
	empty := &logical.MCPCall{}
	if got := callMatchArgString(empty, "x"); got != "" {
		t.Errorf("nil MatchArgs: got %q, want empty", got)
	}
	withArgs := &logical.MCPCall{MatchArgs: map[string]logical.ParamValue{}}
	if got := callMatchArgString(withArgs, "x"); got != "" {
		t.Errorf("missing key: got %q, want empty", got)
	}
}
