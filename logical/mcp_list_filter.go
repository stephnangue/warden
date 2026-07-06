// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package logical

// MCPListFilter directs a gateway to prune an MCP list-method response to the
// items the caller is actually allowed to use, so discovery matches
// enforcement: what an agent sees in tools/list is what it can call.
//
// The policy layer builds it (over the matched mcp{} rule-sets) and hangs it
// on Request.MCPListFilter when it allows a list request whose family the
// policy governs. A gateway that finds it non-nil buffers the upstream list
// response and drops every item whose name Keep rejects; a nil filter means
// "stream the response verbatim". Keep carries the policy semantics — the
// gateway only supplies the item names — so providers need no policy
// knowledge and the filter can't drift from the call-time gate.
type MCPListFilter struct {
	// ListMethod is the list method whose response this filters:
	// "tools/list", "resources/list", or "prompts/list".
	ListMethod string

	// Keep reports whether the named item stays in the filtered response.
	// name is the item's identity as the matching call-time gate reads it —
	// the tool/prompt name, or the resource uri — in its original case.
	Keep func(name string) bool
}
