// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package logical

// MCPPolicyEnforced is implemented by backends that participate in CBP
// `mcp { }` body-authoritative policy enforcement. The core handler
// calls ShouldEnforceMCPPolicy on every matched backend; when it
// returns enforce=true the handler buffers the request body (up to
// cap bytes), strict-parses it as JSON-RPC, and stashes the resulting
// MCPRequestDescriptor on the request before policy evaluation runs.
//
// This interface is the per-backend opt-in. The marker pattern mirrors
// StreamBodyParser so reviewers can pattern-match the shape, and lets
// the trigger stay a compile-time type assertion rather than a string-
// prefix sniff or mount-class enumeration change.
//
// Implementations of MCPPolicyEnforced MUST NOT also opt into
// StreamBodyParser with ShouldParseStreamBody returning true: the
// stream-body parser would consume req.HTTPRequest.Body before the
// MCP extractor runs, leaving the extractor nothing to read. Backends
// that need both behaviours on different sub-paths must scope each
// hook by request shape so their domains do not overlap.
type MCPPolicyEnforced interface {
	// ShouldEnforceMCPPolicy reports whether this request on this
	// backend is subject to `mcp { }` body-based enforcement, and the
	// maximum body size in bytes the policy extractor may buffer.
	//
	// cap <= 0 falls back to framework.DefaultMaxBodySize at the
	// extractor. cap is ignored when enforce is false. Returning the
	// cap here (rather than having the extractor reach into the
	// backend's persisted config) keeps the policy-eval path from
	// duplicating httpproxy's max_body_size config-resolution work.
	//
	// Backends typically gate on request method and Content-Type:
	// MCP enforcement is only meaningful for POSTed JSON-RPC bodies,
	// so GET (SSE reconnect) and DELETE (session close) traffic should
	// return enforce=false.
	ShouldEnforceMCPPolicy(req *Request) (enforce bool, cap int64)
}
