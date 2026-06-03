// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// extractMCPDescriptor populates req.MCPDescriptor based on whether
// the routed backend opts into MCP policy enforcement via the
// logical.MCPPolicyEnforced interface. The descriptor has three
// terminal shapes consumed by decideMCP — see decideMCP's doc for the
// tri-state contract:
//
//  1. Nil — backend does not implement MCPPolicyEnforced at all. If an
//     mcp{} block is bound to such a path that's an operator misconfig
//     and decideMCP fails closed with missing_body.
//
//  2. Non-nil, empty (Calls nil, ParseErr nil) — backend implements
//     the interface but ShouldEnforceMCPPolicy returned enforce=false
//     for THIS request (typically a non-POST verb on a multi-method
//     MCP endpoint, or a non-JSON Content-Type). mcp{} is body-
//     authoritative and cannot meaningfully gate a body-less request,
//     so decideMCP skips evaluation and lets the cap-level policy
//     decide. This is the path that lets MCP Streamable HTTP's GET
//     (notification SSE stream) and DELETE (session terminate) verbs
//     share the same URL with the POST that carries JSON-RPC.
//
//  3. Non-nil with Calls or ParseErr populated — backend opted in and
//     extraction either succeeded (Calls) or failed in a typed way
//     (ParseErr). decideMCP runs the body-authoritative matcher.
//
// The body is read up to cap+1 bytes via io.LimitReader so an
// oversize signal is distinguishable from an at-cap read, and
// restored via io.NopCloser(bytes.NewReader(buf)) so the downstream
// proxy receives the bytes unchanged. The full extraction path is
// panic-safe — any panic from the strict parser is recovered and
// surfaced as a malformed_jsonrpc ParseErr rather than propagating
// into the request handler.
func (c *Core) extractMCPDescriptor(_ context.Context, req *logical.Request, backend logical.Backend) {
	if req == nil || backend == nil {
		return
	}
	mcp, ok := backend.(logical.MCPPolicyEnforced)
	if !ok {
		return // Shape 1: leave descriptor nil.
	}
	enforce, maxBody := mcp.ShouldEnforceMCPPolicy(req)
	if !enforce {
		// Shape 2: install the empty sentinel so decideMCP can tell
		// "backend declined for this request" apart from "no MCP-aware
		// backend handled this request at all". Without this branch,
		// MCP Streamable HTTP's GET/DELETE on the same URL as POST
		// would deny with missing_body, breaking the SSE notification
		// stream every spec-compliant MCP client opens.
		req.MCPDescriptor = &logical.MCPRequestDescriptor{}
		return
	}
	if maxBody <= 0 {
		maxBody = framework.DefaultMaxBodySize
	}

	desc := &logical.MCPRequestDescriptor{}
	defer func() {
		if r := recover(); r != nil {
			// Drop any partial Calls so the matcher's invariant
			// "ParseErr non-nil ⇒ Calls unspecified" stays sound even
			// if a panic fires mid-Calls-loop.
			desc.Calls = nil
			desc.ParseErr = &logical.MCPParseError{
				Kind: logical.MCPParseKindMalformedJSONRPC,
				Msg:  "mcp extractor panic recovered",
			}
		}
		req.MCPDescriptor = desc
	}()

	if req.HTTPRequest == nil || req.HTTPRequest.Body == nil {
		desc.ParseErr = &logical.MCPParseError{
			Kind: logical.MCPParseKindMalformedJSONRPC,
			Msg:  "request body absent",
		}
		return
	}

	body, err := io.ReadAll(io.LimitReader(req.HTTPRequest.Body, maxBody+1))
	if err != nil {
		desc.ParseErr = &logical.MCPParseError{
			Kind: logical.MCPParseKindMalformedJSONRPC,
			Msg:  err.Error(),
		}
		return
	}
	_ = req.HTTPRequest.Body.Close()
	// Body restored (up to maxBody+1 bytes) before any further
	// decision so the downstream proxy can read it. On oversize, the
	// matcher denies so the proxy doesn't run; on parse error, same.
	req.HTTPRequest.Body = io.NopCloser(bytes.NewReader(body))

	if int64(len(body)) > maxBody {
		desc.ParseErr = &logical.MCPParseError{
			Kind: logical.MCPParseKindOversizedBody,
			Msg:  "request body exceeds max_body_size",
		}
		return
	}

	reqs, perr := ParseJSONRPCStrict(body)
	if perr != nil {
		desc.ParseErr = &logical.MCPParseError{
			Kind: string(perr.Kind),
			Msg:  perr.Msg,
		}
		return
	}

	desc.Calls = make([]logical.MCPCall, len(reqs))
	for i, r := range reqs {
		desc.Calls[i] = logical.MCPCall{
			Method:     r.Method,
			Name:       r.Name,
			MatchArgs:  classifyArgs(r.Arguments),
			BatchIndex: i,
		}
	}
}

// classifyArgs typifies each tools/call argument from raw JSON bytes
// into a matcher-ready ParamValue. Non-scalar values are tagged
// Object/Array so the matcher can treat them as missing for scalar
// pattern matching. Returns nil when args is nil so the matcher can
// distinguish "no arguments field" from "arguments: {}" (which yields
// a non-nil empty map).
func classifyArgs(args map[string]json.RawMessage) map[string]logical.ParamValue {
	if args == nil {
		return nil
	}
	out := make(map[string]logical.ParamValue, len(args))
	for k, raw := range args {
		out[k] = classifyParam(raw)
	}
	return out
}

// classifyParam inspects the first non-whitespace byte of the raw
// JSON value to classify the kind cheaply, then unmarshals scalars
// into Str. Malformed bytes for a tagged kind fall through to
// ParamMissing — the strict parser already rejected structurally bad
// JSON, so this is a defensive belt against unexpected drift.
func classifyParam(raw json.RawMessage) logical.ParamValue {
	if len(raw) == 0 {
		return logical.ParamValue{Kind: logical.ParamMissing}
	}
	first := byte(0)
	found := false
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		}
		first = b
		found = true
		break
	}
	if !found {
		// All-whitespace RawMessage shouldn't happen in practice
		// (json.RawMessage strips leading whitespace at decode), but
		// fail closed if it does.
		return logical.ParamValue{Kind: logical.ParamMissing}
	}
	switch first {
	case '{':
		return logical.ParamValue{Kind: logical.ParamObject}
	case '[':
		return logical.ParamValue{Kind: logical.ParamArray}
	case 'n':
		return logical.ParamValue{Kind: logical.ParamNull}
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return logical.ParamValue{Kind: logical.ParamMissing}
		}
		return logical.ParamValue{Kind: logical.ParamString, Str: s}
	case 't', 'f':
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return logical.ParamValue{Kind: logical.ParamMissing}
		}
		s := "false"
		if b {
			s = "true"
		}
		return logical.ParamValue{Kind: logical.ParamBool, Str: s}
	default:
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return logical.ParamValue{Kind: logical.ParamMissing}
		}
		return logical.ParamValue{Kind: logical.ParamNumber, Str: n.String()}
	}
}
