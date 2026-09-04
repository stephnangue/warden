//go:build e2e

package fullchain

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// The other direction of mcp policy. A tools/list is gated on the request side
// like anything else — the method has to be permitted at all — but its *content*
// is decided on the way back, by rewriting the response to drop tools the caller
// may not invoke. Without that, a policy forbids a tool while still advertising
// it, and an agent discovers capabilities it will be refused. The failure is a
// confused agent rather than a breach, but the listing is the only thing most
// clients ever read.
//
// Note what decides the filter: a tool survives if the caller could *call* it,
// so these rows depend on tools/call being permitted by the shared policy block,
// not merely tools/list. Trimming that block to tools/list alone would empty
// every listing.
//
// The filtering itself is well covered in-process, in core and in the filter
// package. What those cannot reach is the wiring: a policy written through the
// API attaching a filter to a real request, and that filter meeting a real
// upstream response on the way back. They construct the filter directly.

// mcpToolsListBody is what the fake upstream returns: a tools/list result
// advertising both the tool the policy allows and the one it does not.
func mcpToolsListBody() string {
	return fmt.Sprintf(
		`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":%q},{"name":%q}]}}`,
		mcpAllowedTool, mcpDeniedTool)
}

// mcpToolsListUpstream answers any request with that listing.
func mcpToolsListUpstream(body string, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

// toolNames pulls the advertised tool names out of a tools/list body.
func toolNames(t *testing.T, body []byte) []string {
	t.Helper()
	var env struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("parsing the tools/list response %q: %v", body, err)
	}
	names := make([]string, 0, len(env.Result.Tools))
	for _, tool := range env.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// TestMCPFilter_DeniedToolIsRemovedFromTheListing drives a tools/list through
// the chain against an upstream that advertises both tools, and expects the
// caller to receive only the one the policy allows.
//
// The upstream is what makes this a wiring test rather than a repeat of the
// in-process ones: the bytes the client reads are the bytes a real server
// produced, rewritten in flight.
func TestMCPFilter_DeniedToolIsRemovedFromTheListing(t *testing.T) {
	ensureEnv(t)
	upstream.SetHandler(t, mcpToolsListUpstream(mcpToolsListBody(), "application/json"))

	status, body, _ := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	})

	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %s)", status, body)
	}

	got := toolNames(t, body)
	if len(got) != 1 || got[0] != mcpAllowedTool {
		t.Errorf("advertised tools: got %v, want only %q — the denied tool was listed to a "+
			"caller who cannot invoke it", got, mcpAllowedTool)
	}

	// The listing came from the upstream rather than from anything Warden
	// substituted, and the fixture really did offer both tools — so the absence
	// above is the filter's doing.
	assertUpstreamServed(t)
	if offered := toolNames(t, []byte(mcpToolsListBody())); len(offered) != 2 {
		t.Fatalf("the fixture advertised %v; it must offer both tools for this row to mean "+
			"anything", offered)
	}
}

// assertUpstreamServed confirms the request reached the upstream exactly once.
//
// Worth stating explicitly on these rows because the response path and the
// transport path fail identically: one error handler answers 502 for a filter
// that refused to forward and for an upstream that could not be reached. Without
// this, a mount pointed at a dead address would satisfy the fail-closed row.
func assertUpstreamServed(t *testing.T) {
	t.Helper()
	if n := len(upstream.Requests()); n != 1 {
		t.Fatalf("upstream served %d requests, want 1 — the response never came from it", n)
	}
}

// TestMCPFilter_UnparseableListingFailsClosed covers the direction that matters
// when something goes wrong. A listing the filter cannot parse cannot be proven
// free of denied tools, so it must not be forwarded — passing the original
// through on a parse error would turn every malformed response into a way to
// advertise everything.
func TestMCPFilter_UnparseableListingFailsClosed(t *testing.T) {
	ensureEnv(t)
	upstream.SetHandler(t, mcpToolsListUpstream(`{"jsonrpc":"2.0","id":1,"result":{"tools":`, "application/json"))

	status, body, _ := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	})

	// 502: the upstream produced something that could not be made safe, which is
	// a gateway failure rather than the caller's fault. Asserted exactly, since
	// "not 200" would also be satisfied by an auth or policy rejection — outcomes
	// meaning the request never reached the filter at all.
	//
	// The status alone does not say the *filter* refused: an unreachable upstream
	// answers 502 through the same error handler. What separates them is that the
	// upstream was reached and did reply.
	assertUpstreamServed(t)
	if status != http.StatusBadGateway {
		t.Errorf("status: got %d, want 502 for a listing that could not be filtered (body: %s)",
			status, body)
	}
	if names := tryToolNames(body); len(names) > 0 {
		t.Errorf("the caller received tool names %v from a listing that could not be filtered", names)
	}
}

// TestMCPFilter_EventStreamListingIsFiltered covers the shape MCP servers
// actually use. Streamable HTTP commonly answers a POST with text/event-stream,
// and the filter dispatches on that content type into a separate branch with its
// own event framing, its own parsing, and its own rewrite.
//
// The JSON row above exercises none of it, so a break confined to the SSE branch
// would leave every listing unfiltered against a real server while the suite
// stayed green.
func TestMCPFilter_EventStreamListingIsFiltered(t *testing.T) {
	ensureEnv(t)

	// A single SSE event carrying the listing, with the framing a Streamable
	// HTTP server emits.
	event := "event: message\ndata: " + mcpToolsListBody() + "\n\n"
	upstream.SetHandler(t, mcpToolsListUpstream(event, "text/event-stream"))

	status, body, _ := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	})

	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %s)", status, body)
	}
	assertUpstreamServed(t)

	// The event framing must survive — a filter that returned bare JSON would
	// break the client's parser as surely as one that leaked a tool.
	if !strings.Contains(string(body), "event: message") {
		t.Errorf("the SSE framing was lost in rewriting: %s", body)
	}

	got := sseToolNames(t, body)
	if len(got) != 1 || got[0] != mcpAllowedTool {
		t.Errorf("advertised tools over SSE: got %v, want only %q", got, mcpAllowedTool)
	}
}

// sseToolNames pulls tool names out of the data line of an SSE listing.
func sseToolNames(t *testing.T, body []byte) []string {
	t.Helper()
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		if payload, ok := strings.CutPrefix(line, "data: "); ok {
			return toolNames(t, []byte(payload))
		}
	}
	t.Fatalf("no data line in the SSE response: %s", body)
	return nil
}

// tryToolNames is toolNames without failing the test when the body is not a
// listing at all — the fail-closed path returns a plain error, not JSON.
func tryToolNames(body []byte) []string {
	var env struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil
	}
	names := make([]string, 0, len(env.Result.Tools))
	for _, tool := range env.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// TestMCPFilter_NoContractDeniesTheListing is the absence deny proven end to
// end, and it is the row that changed direction. A mount with a capability
// grant and no tool contract used to return the upstream's whole catalog; it
// now refuses, and the upstream is never reached at all.
//
// That inversion is the point of the contract being a separate document: the
// state an operator lands in by forgetting to attach one is no longer
// indistinguishable from deliberately opening the mount.
func TestMCPFilter_NoContractDeniesTheListing(t *testing.T) {
	ensureEnv(t)
	upstream.SetHandler(t, mcpToolsListUpstream(mcpToolsListBody(), "application/json"))

	status, body, _ := h.ChainRequest(t, leaderPort, mcpNoContractEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpNoContractEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	})

	if status != http.StatusForbidden {
		t.Fatalf("status: got %d, want 403 (body: %s)", status, body)
	}
	if names := tryToolNames(body); len(names) != 0 {
		t.Errorf("a refused listing advertised %v — nothing may be disclosed", names)
	}
	if n := len(upstream.Requests()); n != 0 {
		t.Errorf("upstream served %d requests, want 0 — the denial must precede the proxy", n)
	}
}

// TestMCPFilter_UnrestrictedContractServesTheWholeListing is the escape hatch.
// A wildcard contract must be equivalent to the ungoverned mount it replaces:
// the caller sees every tool the upstream advertises, unmodified.
func TestMCPFilter_UnrestrictedContractServesTheWholeListing(t *testing.T) {
	ensureEnv(t)
	upstream.SetHandler(t, mcpToolsListUpstream(mcpToolsListBody(), "application/json"))

	status, body, _ := h.ChainRequest(t, leaderPort, mcpGitHubEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpGitHubEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	})

	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %s)", status, body)
	}
	got := toolNames(t, body)
	if len(got) != 2 {
		t.Errorf("advertised tools: got %v, want both — a wildcard contract must not prune", got)
	}
	assertUpstreamServed(t)
}

// TestMCPFilter_UnrestrictedContractDoesNotBufferLargeListings is the guard on
// the no-op short-circuit, and the row most likely to be found in production
// rather than in CI without it.
//
// Attaching a keep-everything filter is not free: the gateway buffers the whole
// upstream response to rewrite it, and fails closed above max_body_size. A
// listing past that cap would therefore start failing on a mount that only ever
// adopted the sanctioned wildcard contract — a catalog large enough to trip it
// is ordinary for a real MCP server.
func TestMCPFilter_UnrestrictedContractDoesNotBufferLargeListings(t *testing.T) {
	ensureEnv(t)

	// Comfortably past the mount's max_body_size, built from tools the contract
	// permits so nothing but the buffering could refuse it.
	var sb strings.Builder
	sb.WriteString(`{"jsonrpc":"2.0","id":1,"result":{"tools":[`)
	for i := 0; i < 40000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"name":"tool_%d","description":"a tool"}`, i)
	}
	sb.WriteString(`]}}`)
	upstream.SetHandler(t, mcpToolsListUpstream(sb.String(), "application/json"))

	status, body, _ := h.ChainRequest(t, leaderPort, mcpGitHubEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpGitHubEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
	})

	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body: %.200s) — an unrestricted contract must "+
			"stream rather than buffer, or a large catalog fails above max_body_size",
			status, body)
	}
	assertUpstreamServed(t)
}
