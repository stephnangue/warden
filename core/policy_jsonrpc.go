// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// maxJSONDepth bounds the recursion of the strict JSON-RPC body walker
// so a pathologically nested payload cannot exhaust the goroutine
// stack. The bound applies inside `params` (one level deep at the start
// of the walk), so a tools/call with arguments nested up to 31 levels
// is still accepted.
const maxJSONDepth = 32

// JSONRPCRequest is one strictly-parsed JSON-RPC 2.0 request extracted
// from a body by ParseJSONRPCStrict. Single-message bodies produce a
// one-element slice; batch bodies produce N elements in array order.
//
// Method is the verbatim string from the body — callers lowercase
// before matching. Name is method-derived: tools/call → params.name,
// resources/read → params.uri, prompts/get → params.name. It is empty
// for other methods. Arguments is the parsed params.arguments map for
// tools/call only (raw bytes per argument key so callers can do their
// own type discrimination); nil for any other method.
//
// RawParams retains the verbatim params bytes for matcher-internal use.
// It is descriptor-only and MUST NOT be copied to MCPDecision, the
// audit record, or the client response.
type JSONRPCRequest struct {
	Method    string
	Name      string
	Arguments map[string]json.RawMessage
	RawParams json.RawMessage
}

// ParseErrorKind enumerates structural-failure deny reasons. Each kind
// maps 1:1 to an MCPDecision rule_type when the evaluator denies in a
// later phase. The matching mcpRuleType* constants in policy_mcp.go are
// introduced in Phase 4; until then this file is the sole source of
// truth for these strings.
type ParseErrorKind string

const (
	ErrKindMalformedJSONRPC ParseErrorKind = "malformed_jsonrpc"
	ErrKindDuplicateKey     ParseErrorKind = "duplicate_key"
	ErrKindOversizedBody    ParseErrorKind = "oversized_body"
	ErrKindBatchEmpty       ParseErrorKind = "batch_empty"
	ErrKindMalformedParams  ParseErrorKind = "malformed_params"
)

// ParseError carries the kind of structural failure plus an
// operator-facing detail Msg. Msg is for server-side logs only and
// MUST NOT be stamped on MCPDecision or surfaced to the client —
// fingerprint hygiene and no leakage of adversary-controlled body
// bytes into operator-visible logs.
type ParseError struct {
	Kind ParseErrorKind
	Msg  string
}

func (e *ParseError) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Kind) + ": " + e.Msg
}

// ParseJSONRPCStrict strictly parses a JSON-RPC 2.0 single-message or
// batch request body and returns the extracted requests. Fails CLOSED
// on any deviation from a well-formed JSON-RPC envelope:
//
//   - UTF-8 BOM prefix.
//   - Top-level value other than an object or an array.
//   - Empty batch ([]).
//   - Trailing data after the top-level value.
//   - Duplicate keys at any depth, in the request object or anywhere in
//     params (Go's encoding/json silently last-wins on duplicates; this
//     parser scans tokens with a per-object seen-set to reject them).
//   - jsonrpc field absent or != "2.0".
//   - method field absent, empty, or non-string.
//   - Unknown top-level keys outside {jsonrpc, method, params, id}.
//   - Nesting deeper than maxJSONDepth inside params.
//   - method-specific shape mismatches: tools/call without params.name
//     or with non-object params.arguments, resources/read without
//     params.uri, prompts/get without params.name.
//
// Callers are responsible for bounding the input size (Content-Length
// and io.LimitReader at the handler boundary) — this function does NOT
// itself enforce a body cap; ErrKindOversizedBody is enumerated for
// callers that need to map their own size-cap failure into the same
// rule_type vocabulary.
func ParseJSONRPCStrict(body []byte) ([]JSONRPCRequest, *ParseError) {
	if hasUTF8BOM(body) {
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "body has UTF-8 BOM"}
	}

	first, ok := firstNonWS(body)
	if !ok {
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "empty body"}
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	var requests []JSONRPCRequest

	switch first {
	case '{':
		req, perr := parseJSONRPCRequest(dec)
		if perr != nil {
			return nil, perr
		}
		requests = []JSONRPCRequest{*req}
	case '[':
		// Consume the opening '['.
		if _, err := dec.Token(); err != nil {
			return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
		}
		for dec.More() {
			req, perr := parseJSONRPCRequest(dec)
			if perr != nil {
				return nil, perr
			}
			requests = append(requests, *req)
		}
		// Consume the closing ']'.
		if _, err := dec.Token(); err != nil {
			return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
		}
		if len(requests) == 0 {
			return nil, &ParseError{Kind: ErrKindBatchEmpty, Msg: "empty batch"}
		}
	default:
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "top-level value must be object or array"}
	}

	// No trailing data after the top-level value. dec.Token() returning
	// io.EOF means clean end; anything else (including a successful
	// token read) is trailing data.
	if _, err := dec.Token(); err != io.EOF {
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "trailing data after JSON-RPC payload"}
	}

	return requests, nil
}

// parseJSONRPCRequest parses one JSON-RPC request object from the
// decoder's current position. The decoder is positioned immediately
// before the opening '{' of the request.
func parseJSONRPCRequest(dec *json.Decoder) (*JSONRPCRequest, *ParseError) {
	tok, err := dec.Token()
	if err != nil {
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "request must be a JSON object"}
	}

	req := &JSONRPCRequest{}
	seen := map[string]struct{}{}
	var jsonrpcSeen, methodSeen bool

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "non-string object key"}
		}
		if _, dup := seen[key]; dup {
			return nil, &ParseError{Kind: ErrKindDuplicateKey, Msg: "duplicate key in request object"}
		}
		seen[key] = struct{}{}

		switch key {
		case "jsonrpc":
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
			}
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "jsonrpc must be a string"}
			}
			if s != "2.0" {
				return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: `jsonrpc must be "2.0"`}
			}
			jsonrpcSeen = true
		case "method":
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
			}
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "method must be a string"}
			}
			if s == "" {
				return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "method must be non-empty"}
			}
			req.Method = s
			methodSeen = true
		case "params":
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
			}
			if perr := validateJSONValue(v, 1); perr != nil {
				return nil, perr
			}
			req.RawParams = v
		case "id":
			// JSON-RPC 2.0 permits string, number, or null. We don't
			// inspect the id; just consume the next value to advance
			// the decoder. validateJSONValue ensures structural
			// soundness if the id happens to be a complex value (some
			// MCP clients have been seen wrapping ids in objects —
			// reject those uniformly).
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
			}
			if perr := validateJSONValue(v, 1); perr != nil {
				return nil, perr
			}
		default:
			return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "unknown top-level key"}
		}
	}

	// Consume the closing '}'.
	if _, err := dec.Token(); err != nil {
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
	}

	if !jsonrpcSeen {
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "missing jsonrpc field"}
	}
	if !methodSeen {
		return nil, &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "missing method field"}
	}

	if perr := extractMethodShape(req); perr != nil {
		return nil, perr
	}

	return req, nil
}

// extractMethodShape populates Name and (for tools/call) Arguments
// from RawParams based on the request method. Method dispatch is
// case-insensitive so a body with method "Tools/CALL" routes to the
// same extractor as "tools/call" — the matcher lowercases for
// comparison and we want consistent semantics at the parser boundary.
// Unrecognised methods leave Name and Arguments zero — the matcher
// will treat them as name-less.
//
// Note: the MCP JSON-RPC spec defines method names as case-sensitive,
// so a body with "Tools/CALL" is technically a different method from
// "tools/call" at the wire level. Our policy gate is intentionally
// MORE permissive: by lowercasing, a case-mismatch attack cannot
// route around the policy. The downstream MCP server still applies
// its own case-sensitive method dispatch and will typically reject
// the mixed-case form — so the request denies either at our policy
// or at the upstream, never silently succeeding.
func extractMethodShape(req *JSONRPCRequest) *ParseError {
	switch strings.ToLower(req.Method) {
	case "tools/call":
		return extractToolsCall(req)
	case "resources/read":
		return extractByParamKey(req, "uri")
	case "prompts/get":
		return extractByParamKey(req, "name")
	}
	return nil
}

// extractToolsCall populates Name from params.name (required, non-empty
// string) and Arguments from params.arguments (optional, must be an
// object when present).
func extractToolsCall(req *JSONRPCRequest) *ParseError {
	if len(req.RawParams) == 0 {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: "tools/call missing params"}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(req.RawParams, &top); err != nil {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: "tools/call params must be an object"}
	}

	nameRaw, ok := top["name"]
	if !ok {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: "tools/call missing params.name"}
	}
	var name string
	if err := json.Unmarshal(nameRaw, &name); err != nil {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: "tools/call params.name must be a string"}
	}
	if name == "" {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: "tools/call params.name must be non-empty"}
	}
	req.Name = name

	if argsRaw, ok := top["arguments"]; ok {
		var args map[string]json.RawMessage
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			return &ParseError{Kind: ErrKindMalformedParams, Msg: "tools/call params.arguments must be an object"}
		}
		req.Arguments = args
	}

	return nil
}

// extractByParamKey extracts Name from the named top-level params key
// (required, non-empty string). Used for resources/read (key = "uri")
// and prompts/get (key = "name").
func extractByParamKey(req *JSONRPCRequest, key string) *ParseError {
	if len(req.RawParams) == 0 {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: req.Method + " missing params"}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(req.RawParams, &top); err != nil {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: req.Method + " params must be an object"}
	}

	raw, ok := top[key]
	if !ok {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: req.Method + " missing params." + key}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: req.Method + " params." + key + " must be a string"}
	}
	if s == "" {
		return &ParseError{Kind: ErrKindMalformedParams, Msg: req.Method + " params." + key + " must be non-empty"}
	}
	req.Name = s
	return nil
}

// validateJSONValue recursively walks a json.RawMessage looking for
// duplicate keys at every object level and bounding recursion depth.
// It does not inspect primitive values beyond confirming they tokenise.
// The caller passes the starting depth (typically 1 — params sits one
// level below the request object).
func validateJSONValue(raw json.RawMessage, startDepth int) *ParseError {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return walkJSONValue(dec, startDepth)
}

func walkJSONValue(dec *json.Decoder, depth int) *ParseError {
	if depth > maxJSONDepth {
		return &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "nested too deep"}
	}
	tok, err := dec.Token()
	if err != nil {
		return &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		// Primitive (string, number, bool, null) — Token() already
		// consumed it; nothing more to walk.
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
			}
			key, ok := keyTok.(string)
			if !ok {
				return &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "non-string object key"}
			}
			if _, dup := seen[key]; dup {
				return &ParseError{Kind: ErrKindDuplicateKey, Msg: "duplicate key in nested object"}
			}
			seen[key] = struct{}{}
			if perr := walkJSONValue(dec, depth+1); perr != nil {
				return perr
			}
		}
		if _, err := dec.Token(); err != nil {
			return &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
		}
	case '[':
		for dec.More() {
			if perr := walkJSONValue(dec, depth+1); perr != nil {
				return perr
			}
		}
		if _, err := dec.Token(); err != nil {
			return &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: err.Error()}
		}
	default:
		return &ParseError{Kind: ErrKindMalformedJSONRPC, Msg: "unexpected delimiter"}
	}
	return nil
}

func hasUTF8BOM(body []byte) bool {
	return len(body) >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF
}

// firstNonWS returns the first non-whitespace byte of body and whether
// such a byte was found. Whitespace per RFC 8259: SP, HT, LF, CR.
func firstNonWS(body []byte) (byte, bool) {
	for _, b := range body {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return b, true
		}
	}
	return 0, false
}
