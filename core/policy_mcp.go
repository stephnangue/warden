// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"encoding/base64"
	"fmt"
	"strings"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
)

// MCP rule_type values produced by AllowOperation when evaluating an
// mcp { } block. These strings appear in audit records under
// auth.policy_results.mcp_decision.rule_type and the response-body
// renderer keys off them to pick the per-rule-type message template.
const (
	mcpRuleTypeAllowedMethods   = "allowed_methods"
	mcpRuleTypeDeniedMethods    = "denied_methods"
	mcpRuleTypeAllowedTools     = "allowed_tools"
	mcpRuleTypeDeniedTools      = "denied_tools"
	mcpRuleTypeAllowedResources = "allowed_resources"
	mcpRuleTypeAllowedPrompts   = "allowed_prompts"
	mcpRuleTypeAllowedParams    = "allowed_params"
	mcpRuleTypeDeniedParams     = "denied_params"
	mcpRuleTypeMissingMethod    = "missing_method_header"
)

// MCP JSON-RPC method names that carry a Mcp-Name header in the
// 2026-07-28 draft. For these methods the name gate (allowed_tools /
// denied_tools / allowed_resources / allowed_prompts) runs after the
// method gate; for any other method the name gate is skipped.
const (
	mcpMethodToolsCall    = "tools/call"
	mcpMethodResourcesRead = "resources/read"
	mcpMethodPromptsGet   = "prompts/get"
)

// MCP-spec header names. Case-insensitive on the wire per RFC 9110;
// net/http canonicalises on read so these casings are what
// http.Header.Get sees regardless of how the client formatted them.
const (
	mcpHeaderMethod = "Mcp-Method"
	mcpHeaderName   = "Mcp-Name"
	// mcpHeaderParamPrefix names the Mcp-Param-{Name} family. Looking
	// up a specific param header uses mcpHeaderParamPrefix + param-name
	// (canonicalised by net/http).
	mcpHeaderParamPrefix = "Mcp-Param-"
)

// ErrMCPPolicyDenied carries the MCPDecision that produced a deny so
// the HTTP response layer can render the OAuth-shaped 403 body and the
// WWW-Authenticate header. Unwraps to sdklogical.ErrPermissionDenied
// so every existing `errors.Is(err, ErrPermissionDenied)` call site
// (status-code mapping, audit, retry logic) keeps working unchanged.
type ErrMCPPolicyDenied struct {
	Decision *logical.MCPDecision
}

func (e *ErrMCPPolicyDenied) Error() string {
	return sdklogical.ErrPermissionDenied.Error()
}

func (e *ErrMCPPolicyDenied) Unwrap() error {
	return sdklogical.ErrPermissionDenied
}

// matchMCPGlob matches a request value against a single canonicalised
// pattern. Patterns use trailing-`*` only (validated at parse time); a
// bare `*` is the zero-prefix wildcard and matches every value. Both
// inputs are expected lowercase — patterns are canonicalised at parse
// time, request values are lowercased once per evaluation by the
// caller.
func matchMCPGlob(value, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	return value == pattern
}

// matchMCPAny returns the first pattern in patterns that matches value,
// or "" if none did. Used by the deny-list short-circuit (any match =
// deny) and the allow-list check (no match = deny via not-in-allow).
func matchMCPAny(value string, patterns []string) string {
	for _, p := range patterns {
		if matchMCPGlob(value, p) {
			return p
		}
	}
	return ""
}

// decodeMCPParamValue decodes the RFC 2047-style encoded-word envelope
// used by the MCP draft for non-ASCII or unsafe Mcp-Param-* values:
//
//	=?base64?<base64-encoded UTF-8>?=
//
// Returns the decoded string when the envelope is well-formed,
// otherwise returns the raw input. Malformed envelopes deliberately
// fall back to the raw value so a bad encoding can't be used to evade
// a deny pattern — the policy still sees what it would have matched
// against had the encoding been honest.
func decodeMCPParamValue(raw string) string {
	const prefix = "=?base64?"
	const suffix = "?="
	if !strings.HasPrefix(raw, prefix) || !strings.HasSuffix(raw, suffix) {
		return raw
	}
	inner := raw[len(prefix) : len(raw)-len(suffix)]
	decoded, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return raw
	}
	return string(decoded)
}

// mcpHeader fetches a header by canonical name from req.HTTPRequest,
// returning "" when the request or header is absent. Centralising the
// nil-check lets the evaluation block stay flat.
func mcpHeader(req *logical.Request, name string) string {
	if req == nil || req.HTTPRequest == nil {
		return ""
	}
	return req.HTTPRequest.Header.Get(name)
}

// mcpHeaderForParam fetches the Mcp-Param-{Name} header value, decoded
// if it was sent as an encoded-word. http.Header.Get already
// canonicalises the lookup key internally so the operator-supplied
// lowercase param-name (e.g. "path") finds the header net/http stored
// as "Mcp-Param-Path".
func mcpHeaderForParam(req *logical.Request, paramName string) string {
	if req == nil || req.HTTPRequest == nil {
		return ""
	}
	raw := req.HTTPRequest.Header.Get(mcpHeaderParamPrefix + paramName)
	if raw == "" {
		return ""
	}
	return decodeMCPParamValue(raw)
}

// nameListForMethod returns the (deny, allow) name-lists that apply to
// the given JSON-RPC method on this rule-set, or (nil, nil) when the
// method is not name-bearing. Centralising the dispatch keeps the
// evaluation block from sprouting a switch in the middle of the loop.
func nameListForMethod(set *CBPMCPRules, method string) (denyList, allowList []string) {
	switch method {
	case mcpMethodToolsCall:
		return set.DeniedTools, set.AllowedTools
	case mcpMethodResourcesRead:
		return nil, set.AllowedResources
	case mcpMethodPromptsGet:
		return nil, set.AllowedPrompts
	}
	return nil, nil
}

// evaluateMCP runs the MCP rule-set slice from CBPPermissions against a
// request and returns a single MCPDecision. Returns nil when the slice
// is empty (no enforcement — the caller continues to parameter checks).
//
// Semantics, per the policy plan:
//   - For each rule-set: short-circuit on the first matching gate
//     (missing-method, denied_methods, allowed_methods miss, name gate,
//     param gate). A set that reaches the end without a deny contributes
//     "allow."
//   - Across sets: OR semantics. If any set allows, the overall decision
//     is allow with that set's MCPDecision. If every set denies, the
//     overall decision is deny with the strongest reason (explicit deny
//     matches > not-in-allow-list > missing-method-header; ties broken
//     by source order).
//
// All comparisons are lowercase; the patterns were lowercased at parse
// time and the request values are lowercased here once per set.
func evaluateMCP(sets []*CBPMCPRules, req *logical.Request) *logical.MCPDecision {
	if len(sets) == 0 {
		return nil
	}

	method := strings.ToLower(mcpHeader(req, mcpHeaderMethod))
	name := strings.ToLower(mcpHeader(req, mcpHeaderName))

	var deny *logical.MCPDecision
	var denyRank int

	for _, set := range sets {
		setDecision := evaluateMCPSet(set, method, name, req)
		if setDecision.Decision == "allow" {
			return setDecision
		}
		// Track strongest-reason across deny sets.
		rank := mcpDenyRank(setDecision.RuleType)
		if deny == nil || rank > denyRank {
			deny = setDecision
			denyRank = rank
		}
	}
	return deny
}

// evaluateMCPSet runs one rule-set against the canonicalised method,
// name, and request. Returns the set's MCPDecision (always non-nil) —
// either an allow with the matching pattern stamped, or a deny with
// the failing gate and pattern stamped.
func evaluateMCPSet(set *CBPMCPRules, method, name string, req *logical.Request) *logical.MCPDecision {
	d := &logical.MCPDecision{Method: method, Name: name}

	// (a) Missing Mcp-Method header → deny. Done before any list
	// check because an empty method can't match anything meaningful
	// and the operator who wrote an mcp{} block wants header-based
	// enforcement.
	if method == "" {
		d.Decision = "deny"
		d.RuleType = mcpRuleTypeMissingMethod
		d.Name = "" // no meaningful name without method
		return d
	}

	// (b) Explicit denied_methods match → deny.
	if m := matchMCPAny(method, set.DeniedMethods); m != "" {
		d.Decision = "deny"
		d.RuleType = mcpRuleTypeDeniedMethods
		d.MatchedRule = m
		return d
	}

	// (c) allowed_methods configured but method not in it → deny.
	if len(set.AllowedMethods) > 0 {
		if m := matchMCPAny(method, set.AllowedMethods); m == "" {
			d.Decision = "deny"
			d.RuleType = mcpRuleTypeAllowedMethods
			return d
		}
	}

	// (d) Name gate for name-bearing methods. Skipped entirely when
	// neither the relevant deny-list nor allow-list is configured for
	// this method — the rule isn't making a name claim.
	if denyList, allowList := nameListForMethod(set, method); len(denyList) > 0 || len(allowList) > 0 {
		if m := matchMCPAny(name, denyList); m != "" {
			d.Decision = "deny"
			d.RuleType = mcpDenyRuleTypeForName(method)
			d.MatchedRule = m
			return d
		}
		if len(allowList) > 0 {
			if m := matchMCPAny(name, allowList); m == "" {
				d.Decision = "deny"
				d.RuleType = mcpAllowRuleTypeForName(method)
				return d
			}
		}
	}

	// (e) Param gate for tools/call only. Each configured key checked
	// independently — AND across keys, OR within a key's value-list.
	if method == mcpMethodToolsCall {
		// Deny-list first per precedence.
		for paramName, patterns := range set.DeniedParams {
			value := mcpHeaderForParam(req, paramName)
			if value == "" {
				continue // missing header can't match a deny pattern
			}
			lowerValue := strings.ToLower(value)
			if m := matchMCPAny(lowerValue, patterns); m != "" {
				d.Decision = "deny"
				d.RuleType = mcpRuleTypeDeniedParams
				d.ParamName = paramName
				d.ParamValue = value
				d.MatchedRule = m
				return d
			}
		}
		for paramName, patterns := range set.AllowedParams {
			value := mcpHeaderForParam(req, paramName)
			if value == "" {
				// Required param missing — deny with empty MatchedRule.
				d.Decision = "deny"
				d.RuleType = mcpRuleTypeAllowedParams
				d.ParamName = paramName
				return d
			}
			lowerValue := strings.ToLower(value)
			if m := matchMCPAny(lowerValue, patterns); m == "" {
				d.Decision = "deny"
				d.RuleType = mcpRuleTypeAllowedParams
				d.ParamName = paramName
				d.ParamValue = value
				return d
			}
		}
	}

	// (f) Nothing denied — this set allows. Record the gate that
	// authorised the request so audit can show which rule fired. The
	// method gate is the universal one to record because it always
	// runs when a set reaches this point.
	d.Decision = "allow"
	d.RuleType = mcpRuleTypeAllowedMethods
	if len(set.AllowedMethods) > 0 {
		// The method matched (we wouldn't have reached step f
		// otherwise), so re-record the matching pattern.
		d.MatchedRule = matchMCPAny(method, set.AllowedMethods)
	} else {
		// No allow-list — the matching "rule" is the method itself
		// (the empty allow-list is "allow all").
		d.MatchedRule = method
	}
	// If the name gate also fired and matched an allow-list, the more
	// specific rule_type is the name gate. Re-derive.
	if _, allowList := nameListForMethod(set, method); len(allowList) > 0 {
		d.RuleType = mcpAllowRuleTypeForName(method)
		d.MatchedRule = matchMCPAny(name, allowList)
	}
	return d
}

// mcpDenyRuleTypeForName maps a name-bearing method to its denied_*
// rule_type string. Only tools/call has a deny-list in v1
// (resources/read and prompts/get use allow-lists only per the policy
// schema), so this is the only reachable case at the caller — the
// fallback is the empty string for forward-compat if a future schema
// version adds denied_resources or denied_prompts.
func mcpDenyRuleTypeForName(method string) string {
	switch method {
	case mcpMethodToolsCall:
		return mcpRuleTypeDeniedTools
	}
	return ""
}

// mcpAllowRuleTypeForName maps a name-bearing method to its allowed_*
// rule_type string.
func mcpAllowRuleTypeForName(method string) string {
	switch method {
	case mcpMethodToolsCall:
		return mcpRuleTypeAllowedTools
	case mcpMethodResourcesRead:
		return mcpRuleTypeAllowedResources
	case mcpMethodPromptsGet:
		return mcpRuleTypeAllowedPrompts
	}
	return ""
}

// mcpDenyRank scores deny reasons for the strongest-reason audit
// selection across multi-set denies. Higher rank wins; ties (same
// rank, multiple sets) are resolved in source order by the caller's
// "first wins on ==" branch in evaluateMCP.
//
//	explicit deny match (denied_*)             → 3
//	not-in-allow-list (allowed_*, no match)    → 2
//	missing_method_header                      → 1
func mcpDenyRank(ruleType string) int {
	switch ruleType {
	case mcpRuleTypeDeniedMethods,
		mcpRuleTypeDeniedTools,
		mcpRuleTypeDeniedParams:
		return 3
	case mcpRuleTypeAllowedMethods,
		mcpRuleTypeAllowedTools,
		mcpRuleTypeAllowedResources,
		mcpRuleTypeAllowedPrompts,
		mcpRuleTypeAllowedParams:
		return 2
	case mcpRuleTypeMissingMethod:
		return 1
	}
	return 0
}

// BuildMCPDenyDescription renders the operator-facing single-sentence
// message returned in the 403 body's error_description field and in
// the WWW-Authenticate header. Exported so the HTTP response layer
// (http package) can consume it without duplicating the template
// table. Per the policy plan Semantics, the templates deliberately
// omit matched_rule and rule_type from the client-visible string —
// disclosure of those stays in the audit log only, and the
// denied/allowed cases for the same name produce identical strings
// so the client can't fingerprint operator policy shape from the
// response.
//
// Strips ASCII control characters from interpolated values defensively
// — MCP headers shouldn't contain CTLs but RFC 7235 disallows them in
// the WWW-Authenticate quoted-string and a malformed header is worse
// than a sanitised one.
func BuildMCPDenyDescription(d *logical.MCPDecision) string {
	if d == nil {
		return "Request denied by policy."
	}
	method := stripCTL(d.Method)
	name := stripCTL(d.Name)
	param := stripCTL(d.ParamName)
	value := stripCTL(d.ParamValue)

	switch d.RuleType {
	case mcpRuleTypeDeniedMethods, mcpRuleTypeAllowedMethods:
		return fmt.Sprintf("Method '%s' not allowed.", method)
	case mcpRuleTypeDeniedTools, mcpRuleTypeAllowedTools:
		return fmt.Sprintf("Tool '%s' not allowed.", name)
	case mcpRuleTypeAllowedResources:
		return fmt.Sprintf("Resource '%s' not allowed.", name)
	case mcpRuleTypeAllowedPrompts:
		return fmt.Sprintf("Prompt '%s' not allowed.", name)
	case mcpRuleTypeDeniedParams:
		return fmt.Sprintf("Parameter '%s'='%s' not allowed.", param, value)
	case mcpRuleTypeAllowedParams:
		if value == "" {
			return fmt.Sprintf("Parameter '%s' required.", param)
		}
		return fmt.Sprintf("Parameter '%s'='%s' not allowed.", param, value)
	case mcpRuleTypeMissingMethod:
		return "Mcp-Method header required."
	}
	return "Request denied by policy."
}

// stripCTL removes ASCII control characters (\x00-\x1F, \x7F) from s.
// Used defensively before interpolating user-supplied values into the
// WWW-Authenticate header per RFC 7235 quoted-string rules.
func stripCTL(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
}
