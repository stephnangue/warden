// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package logical

// MCPRequestDescriptor carries the result of strictly parsing an
// MCP-enforced backend's request body. Stashed on *Request by the core
// handler's extractor; consumed by the policy evaluator in a later
// phase.
//
// One of two terminal states: ParseErr is non-nil (Calls is then
// unspecified — the matcher must not consult it) or ParseErr is nil
// and Calls is populated. A nil *MCPRequestDescriptor on *Request
// means the request was not subject to MCP enforcement (backend opted
// out, or backend declined this particular request).
type MCPRequestDescriptor struct {
	Calls    []MCPCall
	ParseErr *MCPParseError
}

// MCPCall is one strictly-parsed JSON-RPC request extracted from the
// body. Single-message bodies produce one MCPCall with BatchIndex 0;
// batch bodies produce N elements in array order.
//
// Method and Name are verbatim from the wire — the matcher lowercases
// at compare time. MatchArgs is populated only for tools/call (from
// params.arguments) so the matcher's denied_params / allowed_params
// can gate on individual argument values. For other methods MatchArgs
// is nil.
type MCPCall struct {
	Method     string
	Name       string
	MatchArgs  map[string]ParamValue
	BatchIndex int
}

// ParamKind classifies the JSON type of a tools/call argument value
// so the matcher can decide which pattern-list semantics apply. Scalar
// kinds (String / Number / Bool) render to Str for string-pattern
// matching; Non-scalar kinds (Object / Array) and Null have empty Str
// and the matcher treats them as missing for deny-list checks and as
// missing-required for allow-list checks.
type ParamKind uint8

const (
	ParamMissing ParamKind = iota
	ParamString
	ParamNumber
	ParamBool
	ParamNull
	ParamObject
	ParamArray
)

// ParamValue is a typed view of one tools/call argument. Str carries
// the matcher-comparable string form: verbatim for strings,
// json.Number stringified for numbers, "true"/"false" for booleans.
// For Null / Object / Array / Missing kinds Str is the zero value.
type ParamValue struct {
	Kind ParamKind
	Str  string
}

// MCPParseError carries the kind of structural failure plus an
// operator-facing detail Msg. Msg is for server-side logs only and
// MUST NOT be stamped on MCPDecision or surfaced to the client —
// fingerprint hygiene and no leakage of adversary-controlled body
// bytes into operator-visible logs.
//
// Kind is one of the MCPParseKind* string constants; the matcher in a
// later phase maps these 1:1 to MCPDecision.RuleType values.
type MCPParseError struct {
	Kind string
	Msg  string
}

// MCPParseKind* enumerate the descriptor-level parse failure modes.
// The string values are the same identifiers used as MCPDecision
// rule_type values, so the mapping is identity rather than a
// per-package translation table.
const (
	MCPParseKindMalformedJSONRPC = "malformed_jsonrpc"
	MCPParseKindDuplicateKey     = "duplicate_key"
	MCPParseKindOversizedBody    = "oversized_body"
	MCPParseKindBatchEmpty       = "batch_empty"
	MCPParseKindMalformedParams  = "malformed_params"
)

// Clone returns a deep copy of the MCPRequestDescriptor. Safe to call
// on a nil receiver (returns nil). The audit layer's request-clone
// path treats MCPRequestDescriptor as a deep-copy field so an async
// audit writer cannot observe mutations made by a concurrent request
// handler — though by current design the descriptor is read-only
// post-extraction.
func (d *MCPRequestDescriptor) Clone() *MCPRequestDescriptor {
	if d == nil {
		return nil
	}
	clone := &MCPRequestDescriptor{}
	if d.Calls != nil {
		clone.Calls = make([]MCPCall, len(d.Calls))
		for i, c := range d.Calls {
			clone.Calls[i] = c.Clone()
		}
	}
	if d.ParseErr != nil {
		errCopy := *d.ParseErr
		clone.ParseErr = &errCopy
	}
	return clone
}

// Clone returns a deep copy of the MCPCall. MatchArgs is a map of
// value-typed ParamValue, so a length-preserving copy of the map
// breaks aliasing.
func (c MCPCall) Clone() MCPCall {
	out := MCPCall{
		Method:     c.Method,
		Name:       c.Name,
		BatchIndex: c.BatchIndex,
	}
	if c.MatchArgs != nil {
		out.MatchArgs = make(map[string]ParamValue, len(c.MatchArgs))
		for k, v := range c.MatchArgs {
			out.MatchArgs[k] = v
		}
	}
	return out
}
