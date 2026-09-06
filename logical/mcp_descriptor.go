// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package logical

import "encoding/json"

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

	// IsBatch records that the body's top-level value was an array. Not
	// recoverable from Calls, since a one-element array and a single
	// object both yield one call — and that is exactly the pair the
	// modern-era batch rejection has to tell apart.
	IsBatch bool

	// ClientInfoName and ClientInfoVersion are the client's
	// self-description, carried for the audit record. Unverified,
	// unauthenticated, and trivially forged: never consult them in a
	// gate.
	ClientInfoName    string
	ClientInfoVersion string
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
//
// URIs is populated only for subscriptions/listen, from
// params.notifications.resourceSubscriptions, and carries the resource
// URIs whose update notifications the caller asked to receive. The
// matcher gates each one against the resources family, so subscribing
// to a resource's update stream requires the same grant as reading it.
// nil for other methods, and for a listen that names no resource.
// RawID carries the JSON-RPC id verbatim so a protocol-level error
// response can echo it, and IDPresent separates a request from a
// notification — JSON-RPC permits a null id, which is present-but-null
// and not the same as absent. Neither is ever matched against; they
// exist so a refusal can be rendered as a well-formed JSON-RPC error
// rather than an opaque HTTP status.
type MCPCall struct {
	Method     string
	Name       string
	MatchArgs  map[string]ParamValue
	URIs       []string
	RawID      json.RawMessage
	IDPresent  bool
	BatchIndex int

	// MetaProtocolVersion is the protocol revision the body declares in
	// params._meta, empty when it declares none. Compared against the
	// transport header so a request cannot claim one revision to Warden
	// and another to whatever reads the body next.
	MetaProtocolVersion string
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

	// MCPParseKindBatchUnsupported refuses a batch from a client announcing
	// a protocol revision that postdates batching's removal from the spec.
	// Distinct from MCPParseKindBatchEmpty, and distinct from a header
	// mismatch: the body is well-formed and the headers describe it
	// correctly — the two claims it makes about itself simply cannot both
	// be true.
	MCPParseKindBatchUnsupported = "batch_unsupported"
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
	clone := &MCPRequestDescriptor{
		IsBatch:           d.IsBatch,
		ClientInfoName:    d.ClientInfoName,
		ClientInfoVersion: d.ClientInfoVersion,
	}
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
// breaks aliasing; URIs is a slice and needs the same treatment, or
// the audit layer's copy would share backing array with the live
// request.
func (c MCPCall) Clone() MCPCall {
	out := MCPCall{
		Method:              c.Method,
		Name:                c.Name,
		IDPresent:           c.IDPresent,
		MetaProtocolVersion: c.MetaProtocolVersion,
		BatchIndex:          c.BatchIndex,
	}
	if c.RawID != nil {
		out.RawID = make(json.RawMessage, len(c.RawID))
		copy(out.RawID, c.RawID)
	}
	if c.MatchArgs != nil {
		out.MatchArgs = make(map[string]ParamValue, len(c.MatchArgs))
		for k, v := range c.MatchArgs {
			out.MatchArgs[k] = v
		}
	}
	if c.URIs != nil {
		out.URIs = make([]string, len(c.URIs))
		copy(out.URIs, c.URIs)
	}
	return out
}
