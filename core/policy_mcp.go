// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"fmt"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logical"
)

// MCP rule_type values produced by AllowOperation when evaluating an
// mcp { } block. These strings appear in audit records under
// auth.policy_results.mcp_decision.rule_type and the response-body
// renderer keys off them to pick the per-rule-type message template.
//
// The structural-failure values (missing_body, malformed_jsonrpc,
// duplicate_key, oversized_body, batch_empty, malformed_params) fire
// when the body-authoritative path cannot evaluate the policy at all —
// no descriptor produced, or descriptor carries a ParseErr from the
// strict JSON-RPC parser. They rank above explicit-deny matches in
// mcpDenyRank so a multi-set deny surfaces the structural reason
// (more informative for operators than "tool not allowed" when the
// body itself was unparseable).
//
// missing_method_header is the legacy header-era sentinel; kept in
// scope for back-compat with existing audit records but never emitted
// on the body-authoritative path.
const (
	mcpRuleTypeAllowedMethods   = "allowed_methods"
	mcpRuleTypeDeniedMethods    = "denied_methods"
	mcpRuleTypeAllowedTools     = "allowed_tools"
	mcpRuleTypeDeniedTools      = "denied_tools"
	mcpRuleTypeAllowedResources = "allowed_resources"
	mcpRuleTypeDeniedResources  = "denied_resources"
	mcpRuleTypeAllowedPrompts   = "allowed_prompts"
	mcpRuleTypeDeniedPrompts    = "denied_prompts"
	mcpRuleTypeAllowedParams    = "allowed_params"
	mcpRuleTypeDeniedParams     = "denied_params"
	mcpRuleTypeCondition        = "condition"
	mcpRuleTypeConditionError   = "condition_error"
	mcpRuleTypeMissingMethod    = "missing_method_header"

	mcpRuleTypeMissingBody      = "missing_body"
	mcpRuleTypeMalformedJSONRPC = "malformed_jsonrpc"
	mcpRuleTypeDuplicateKey     = "duplicate_key"
	mcpRuleTypeOversizedBody    = "oversized_body"
	mcpRuleTypeBatchEmpty       = "batch_empty"
	mcpRuleTypeMalformedParams  = "malformed_params"
)

// MCP JSON-RPC method names that carry name-bearing semantics. For
// these methods the name gate (allowed_tools / denied_tools /
// allowed_resources / allowed_prompts) runs after the method gate;
// for any other method the name gate is skipped.
const (
	mcpMethodToolsCall     = "tools/call"
	mcpMethodResourcesRead = "resources/read"
	mcpMethodPromptsGet    = "prompts/get"
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

// nameListForMethod returns the (deny, allow) name-lists that apply to
// the given JSON-RPC method on this rule-set, or (nil, nil) when the
// method is not name-bearing. Centralising the dispatch keeps the
// evaluation block from sprouting a switch in the middle of the loop.
func nameListForMethod(set *CBPMCPRules, method string) (denyList, allowList []string) {
	switch method {
	case mcpMethodToolsCall:
		return set.DeniedTools, set.AllowedTools
	case mcpMethodResourcesRead:
		return set.DeniedResources, set.AllowedResources
	case mcpMethodPromptsGet:
		return set.DeniedPrompts, set.AllowedPrompts
	}
	return nil, nil
}

// decideMCP is the production entry point called from
// AllowOperation when the matched permissions carry a non-empty
// mcp { } rule-set slice. It bridges req.MCPDescriptor's four
// terminal states to MCPDecision (see extractMCPDescriptor for how
// each state is produced):
//
//   - Nil descriptor — no MCP-aware backend handled this request.
//     If an operator bound mcp{} to a non-MCP path, that's a misconfig
//     and we fail closed with missing_body. This is the safety net.
//
//   - Non-nil, empty descriptor (Calls nil, ParseErr nil) — the
//     backend is MCP-aware but ShouldEnforceMCPPolicy declined for
//     this request (typically a non-POST verb, or a non-JSON
//     Content-Type). The mcp{} block is body-authoritative; a verb
//     with no body cannot be governed by method/tool/param allow-
//     lists, so we return nil to skip mcp{} evaluation and let the
//     cap-level check decide. This is what makes MCP Streamable
//     HTTP's GET (notification SSE stream) and DELETE (session
//     terminate) work on the same URL that POST gates.
//
//   - descriptor.ParseErr non-nil — strict JSON-RPC parse failed.
//     Deny with the typed rule_type (malformed_jsonrpc, duplicate_key,
//     oversized_body, etc). ParseErr.Msg is operator-facing only and
//     never copied into the decision.
//
//   - descriptor.Calls populated — body parsed cleanly. Delegate to
//     evaluateMCPDescriptor for body-driven gate evaluation.
//
// A nil return from decideMCP means "this policy layer has no opinion
// — fall through to the next check". A non-nil deny is binding.
//
// Every returned decision passes through sanitizeMCPDecision so
// adversary-controlled bytes don't leak into audit or response
// rendering.
func decideMCP(sets []*CBPMCPRules, req *logical.Request, te *logical.TokenEntry, now time.Time) *logical.MCPDecision {
	if len(sets) == 0 {
		return nil
	}
	var d *logical.MCPDecision
	desc := req.MCPDescriptor
	switch {
	case desc == nil:
		d = &logical.MCPDecision{
			Decision: "deny",
			RuleType: mcpRuleTypeMissingBody,
		}
	case desc.Calls == nil && desc.ParseErr == nil:
		// Backend opted out of MCP enforcement for this specific
		// request shape (e.g. non-POST verb on a multi-method MCP
		// endpoint). The mcp{} block doesn't apply to body-less
		// verbs; return nil so the cap-level check decides.
		return nil
	case desc.ParseErr != nil:
		d = &logical.MCPDecision{
			Decision: "deny",
			RuleType: desc.ParseErr.Kind,
		}
	default:
		d = evaluateMCPDescriptor(sets, desc, req, te, now)
		if d == nil {
			// Defence in depth: evaluateMCPDescriptor returns nil
			// only for empty sets (handled above) or for a non-nil
			// descriptor with zero calls (the extractor's invariant
			// for the "populated" arm rules this out — Calls is
			// always non-empty when ParseErr is nil and the empty
			// sentinel is intercepted above). decideMCP is the
			// policy-layer boundary and cannot trust its input.
			// Fail closed.
			d = &logical.MCPDecision{
				Decision: "deny",
				RuleType: mcpRuleTypeMissingBody,
			}
		}
	}
	sanitizeMCPDecision(d)
	return d
}

// evaluateMCPDescriptor is the body-authoritative matcher. Consumes a
// strictly-parsed descriptor + the policy rule-set slice; returns the
// MCPDecision. Single-call descriptors return the call's decision
// directly. Multi-call (batch) descriptors short-circuit at the first
// denying call (stamping BatchIndex on the returned decision); allow
// only if every call allows — single-fail-all-fail per the policy plan.
//
// Returns nil when sets is empty (no enforcement) or when the
// descriptor carries no calls. The caller in AllowOperation handles
// structural failures (nil descriptor, ParseErr non-nil) before
// invoking this function.
func evaluateMCPDescriptor(sets []*CBPMCPRules, desc *logical.MCPRequestDescriptor, req *logical.Request, te *logical.TokenEntry, now time.Time) *logical.MCPDecision {
	if len(sets) == 0 {
		return nil
	}
	if desc == nil || len(desc.Calls) == 0 {
		return nil
	}

	// Build the request-wide activation once (reused across the batch) only
	// when at least one set carries a CEL condition; nil otherwise so the
	// common no-condition path allocates nothing extra.
	var act *celActivation
	if mcpSetsHaveCondition(sets) {
		act = newCELActivation(celRequestInputFromRequest(req), celTokenInputFromEntry(te, now), now, nil)
	}

	batch := len(desc.Calls) > 1
	var lastAllow *logical.MCPDecision
	for i := range desc.Calls {
		call := &desc.Calls[i]
		if act != nil {
			act.call = buildCallNS(call.Method, call.Name, call.MatchArgs, call.BatchIndex)
		}
		d := evaluateMCPCall(sets, call, act)
		if d.Decision == "deny" {
			if batch {
				idx := call.BatchIndex
				d.BatchIndex = &idx
			}
			return d
		}
		lastAllow = d
	}
	return lastAllow
}

func mcpSetsHaveCondition(sets []*CBPMCPRules) bool {
	for _, s := range sets {
		if s != nil && s.Condition != nil {
			return true
		}
	}
	return false
}

// evaluateMCPCall runs all rule-sets against one MCPCall and applies
// the cross-set OR / strongest-reason-deny semantics. Lowercases
// method/name once at the boundary so per-set comparisons stay cheap.
// act carries the per-call CEL activation (nil when no set has a condition).
func evaluateMCPCall(sets []*CBPMCPRules, call *logical.MCPCall, act *celActivation) *logical.MCPDecision {
	method := strings.ToLower(call.Method)
	name := strings.ToLower(call.Name)

	var deny *logical.MCPDecision
	var denyRank int

	for _, set := range sets {
		setDecision := evaluateMCPSetForCall(set, method, name, call, act)
		if setDecision.Decision == "allow" {
			return setDecision
		}
		rank := mcpDenyRank(setDecision.RuleType)
		if deny == nil || rank > denyRank {
			deny = setDecision
			denyRank = rank
		}
	}
	return deny
}

// evaluateMCPSetForCall runs one rule-set against the canonicalised
// method, name, and call. Returns the set's MCPDecision (always non-
// nil) — either an allow with the matching pattern stamped, or a
// deny with the failing gate and pattern stamped. Reads param values
// from call.MatchArgs.
func evaluateMCPSetForCall(set *CBPMCPRules, method, name string, call *logical.MCPCall, act *celActivation) *logical.MCPDecision {
	d := &logical.MCPDecision{Method: method, Name: name}

	// (a) Missing method → deny. The body-authoritative parser
	// rejects an empty method as malformed_jsonrpc before we get
	// here, so this branch is now reachable only via test-synthesised
	// descriptors that intentionally drop method. Fail closed.
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
	// neither the relevant deny-list nor allow-list is configured
	// for this method — the rule isn't making a name claim.
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

	// (e) CEL condition gate (last, after the structured gates). Fail-closed:
	// an erroring or false condition denies. Evaluated against the request /
	// token namespaces plus this call.
	if set.Condition != nil {
		ok, err := evalCELCondition(set.Condition.Program, act)
		if err != nil {
			d.Decision = "deny"
			d.RuleType = mcpRuleTypeConditionError
			d.Condition = &logical.ConditionResult{Decision: "deny", Expression: set.Condition.Source, ErrorKind: celErrorKind(err), Inputs: resolveConditionInputs(set.Condition.RefPaths, act)}
			return d
		}
		if !ok {
			d.Decision = "deny"
			d.RuleType = mcpRuleTypeCondition
			d.Condition = &logical.ConditionResult{Decision: "deny", Expression: set.Condition.Source, Inputs: resolveConditionInputs(set.Condition.RefPaths, act)}
			return d
		}
	}

	// (f) Nothing denied — this set allows. Record the gate that
	// authorised the request so audit can show which rule fired.
	d.Decision = "allow"
	d.RuleType = mcpRuleTypeAllowedMethods
	if set.Condition != nil {
		d.Condition = &logical.ConditionResult{Decision: "allow", Expression: set.Condition.Source, Inputs: resolveConditionInputs(set.Condition.RefPaths, act)}
	}
	if len(set.AllowedMethods) > 0 {
		d.MatchedRule = matchMCPAny(method, set.AllowedMethods)
	} else {
		d.MatchedRule = method
	}
	if _, allowList := nameListForMethod(set, method); len(allowList) > 0 {
		d.RuleType = mcpAllowRuleTypeForName(method)
		d.MatchedRule = matchMCPAny(name, allowList)
	}
	return d
}

// mcpDenyRuleTypeForName maps a name-bearing method to its denied_*
// rule_type string.
func mcpDenyRuleTypeForName(method string) string {
	switch method {
	case mcpMethodToolsCall:
		return mcpRuleTypeDeniedTools
	case mcpMethodResourcesRead:
		return mcpRuleTypeDeniedResources
	case mcpMethodPromptsGet:
		return mcpRuleTypeDeniedPrompts
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
// rank, multiple sets) are resolved in source order by the caller.
//
//	structural failure (missing_body etc.)     → 4
//	explicit deny match (denied_*)             → 3
//	not-in-allow-list (allowed_*, no match)    → 2
//	missing_method_header (legacy)             → 1
//
// Structural failures outrank explicit deny matches so a multi-set
// scenario where one set evaluates fine but another encountered a
// structural problem surfaces the more informative reason. In
// practice structural failures are produced by AllowOperation BEFORE
// evaluateMCPDescriptor runs, so cross-set ties between structural
// and rule-driven denies are unusual; the rank still matters when a
// future change starts producing them from inside the matcher.
func mcpDenyRank(ruleType string) int {
	switch ruleType {
	case mcpRuleTypeMissingBody,
		mcpRuleTypeMalformedJSONRPC,
		mcpRuleTypeDuplicateKey,
		mcpRuleTypeOversizedBody,
		mcpRuleTypeBatchEmpty,
		mcpRuleTypeMalformedParams:
		return 4
	case mcpRuleTypeDeniedMethods,
		mcpRuleTypeDeniedTools,
		mcpRuleTypeDeniedResources,
		mcpRuleTypeDeniedPrompts,
		mcpRuleTypeDeniedParams,
		mcpRuleTypeCondition,
		mcpRuleTypeConditionError:
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
// disclosure of those stays in the audit log only, and the denied /
// allowed cases for the same name produce identical strings so the
// client can't fingerprint operator policy shape from the response.
//
// Structural-failure cases (missing_body, malformed_jsonrpc, etc.)
// return generic single sentences that intentionally do NOT include
// the parse error's Msg, the offending JSON-RPC offset, the duplicate
// key name, or any other body-derived detail — same fingerprint
// hygiene + no leakage of adversary-controlled body bytes into the
// client response.
//
// All interpolated values are CTL-stripped defensively even though
// sanitizeMCPDecision already strips them at stamping time, so a
// directly-constructed MCPDecision (e.g. from tests) still renders
// cleanly.
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
	case mcpRuleTypeDeniedResources, mcpRuleTypeAllowedResources:
		return fmt.Sprintf("Resource '%s' not allowed.", name)
	case mcpRuleTypeDeniedPrompts, mcpRuleTypeAllowedPrompts:
		return fmt.Sprintf("Prompt '%s' not allowed.", name)
	case mcpRuleTypeDeniedParams:
		return fmt.Sprintf("Parameter '%s'='%s' not allowed.", param, value)
	case mcpRuleTypeAllowedParams:
		if value == "" {
			return fmt.Sprintf("Parameter '%s' required.", param)
		}
		return fmt.Sprintf("Parameter '%s'='%s' not allowed.", param, value)
	case mcpRuleTypeMissingBody:
		return "Request body required."
	case mcpRuleTypeMalformedJSONRPC:
		return "Request body is not a valid JSON-RPC request."
	case mcpRuleTypeDuplicateKey:
		return "Request body contains duplicate keys."
	case mcpRuleTypeOversizedBody:
		return "Request body exceeds maximum size."
	case mcpRuleTypeBatchEmpty:
		return "Request batch is empty."
	case mcpRuleTypeMalformedParams:
		return "Request params have unexpected shape."
	case mcpRuleTypeMissingMethod:
		return "Request method required."
	}
	return "Request denied by policy."
}

// sanitizeMCPDecision strips ASCII control characters from every
// string field on the decision before it leaves the policy layer.
// Adversary-controlled body bytes (Method, Name, ParamValue) might
// otherwise propagate into audit logs (log injection) or into the
// WWW-Authenticate quoted-string. Operator-set values (ParamName,
// MatchedRule) come from policy HCL and are presumed clean, but
// stripping them too is cheap defence in depth.
func sanitizeMCPDecision(d *logical.MCPDecision) {
	if d == nil {
		return
	}
	d.Method = stripCTL(d.Method)
	d.Name = stripCTL(d.Name)
	d.MatchedRule = stripCTL(d.MatchedRule)
	d.ParamName = stripCTL(d.ParamName)
	d.ParamValue = stripCTL(d.ParamValue)
	d.Condition.Sanitize()
}

// stripCTL removes ASCII control characters (\x00-\x1F, \x7F) from s.
// Used by sanitizeMCPDecision at stamping time and by
// BuildMCPDenyDescription at render time — the description renderer
// keeps the strip because directly-constructed MCPDecision values
// (e.g. from tests) bypass the sanitizer.
func stripCTL(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7F {
			return -1
		}
		return r
	}, s)
}
