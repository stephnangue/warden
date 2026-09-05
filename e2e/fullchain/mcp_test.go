//go:build e2e

package fullchain

import (
	"strconv"
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// mcp is the only provider whose authorization depends on the request *body*.
// Everything else in this suite is decided by path and capability; here a policy
// names the tools a caller may invoke, and the decision needs the JSON-RPC call
// itself.
//
// The decision logic is covered thoroughly in-process — core has several files
// on MCP policy parsing, evaluation and list filtering. What none of them cover is
// the wiring: that a policy written through the API, stored, attached to a token
// minted for a certificate agent, and evaluated against a real request body,
// actually reaches the enforcement point. Those tests construct a Core directly.
//
// Its credential extractor accepts five types and reads a different field for
// three of them. The api_key and github_token fields are both covered here — the
// two that read different fields and are cheapest to mint — and all five,
// including their empty-token branches, in provider/mcp's unit tests.

const (
	mcpAPIKey      = "fc-mcp-not-a-real-key"
	mcpGitHubToken = "fc-mcp-not-a-real-github-token"
	mcpAllowedTool = "fc_allowed_tool"
	mcpDeniedTool  = "fc_denied_tool"
)

var mcpEnv = h.ProviderEnv{
	Mount:      "fc-mcp",
	Type:       "mcp",
	URLKey:     "mcp_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": mcpAPIKey},
	// Naming one tool is what opts the mount into body-authoritative
	// enforcement; with no MCP contract in scope the body is never inspected
	// and every JSON-RPC call the capability allows would go through.
	MCPPolicyRules: `  methods { allowed = ["tools/call", "tools/list"] }
  tools { allowed = ["` + mcpAllowedTool + `"] }`,
}

// The github_token arm needs its own mount: a role binds one spec, and a variant
// spec would share this env's credential type. Its only job is to prove the
// extractor reads "token" rather than "api_key" for that type — a mis-wired
// field would fail as "missing token", indistinguishable from an empty one.
var mcpGitHubEnv = h.ProviderEnv{
	Mount:      "fc-mcp-github",
	Type:       "mcp",
	URLKey:     "mcp_url",
	CredType:   "github_token",
	CredConfig: map[string]string{"token": mcpGitHubToken},
}

func mcpToolCall(tool string) string {
	return mcpToolCallID(tool, 1)
}

func mcpToolCallID(tool string, id int) string {
	return `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) + `,"method":"tools/call","params":{"name":"` + tool + `"}}`
}

// TestMCP_AllowedToolReachesUpstream is the positive half. It also confirms the
// credential extractor picked the right field for this credential type — the
// same 200 covers both, since a request that authorised but injected nothing
// would arrive without an Authorization header.
func TestMCP_AllowedToolReachesUpstream(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         mcpToolCall(mcpAllowedTool),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + mcpAPIKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestMCP_BatchIsProxied is the end-to-end half of core's TestMCPE2E_BatchAllAllowed.
//
// A JSON-RPC batch is a top-level JSON array, and no mount could carry one: the
// authorization path decoded every request body into a string-keyed map, which an
// array cannot be, and the request died there. The unit tests exercised batches by
// calling the extractor directly, so they passed throughout — this row is the only
// place the wiring is checked.
//
// Every call names the allowed tool, so the batch is allowed whole. It must also
// arrive whole: a batch that authorised but reached the upstream re-serialised or in
// pieces would be a different bug wearing the same 200.
func TestMCP_BatchIsProxied(t *testing.T) {
	ensureEnv(t)
	upstream.Reset()

	batch := `[` + mcpToolCallID(mcpAllowedTool, 1) + `,` + mcpToolCallID(mcpAllowedTool, 2) + `]`

	status, body, _ := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         batch,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + mcpAPIKey},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})

	reqs := upstream.Requests()
	if got := string(reqs[len(reqs)-1].Body); got != batch {
		t.Errorf("upstream body: got %s, want %s", got, batch)
	}
}

// TestMCP_BatchWithDeniedCallIsRefused is the counterpart, and the reason the row
// above is not enough on its own: now that a batch can be carried, the filter has to
// still read every call in it. One denied tool among allowed ones refuses the whole
// batch, before anything is forwarded — a filter that inspected only the first call
// would pass the row above and leak here.
func TestMCP_BatchWithDeniedCallIsRefused(t *testing.T) {
	ensureEnv(t)
	upstream.Reset()

	status, body, _ := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         `[` + mcpToolCallID(mcpAllowedTool, 1) + `,` + mcpToolCallID(mcpDeniedTool, 2) + `]`,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})
}

// TestMCP_GitHubTokenArmReadsItsOwnField covers the second field the extractor
// reads. Both arms emit the same Bearer scheme, so the only thing separating
// them is which key the token was taken from — and reading the wrong one yields
// "missing token", a failure indistinguishable from an unset credential.
func TestMCP_GitHubTokenArmReadsItsOwnField(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, mcpGitHubEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpGitHubEnv.CertRole(),
		Body:         mcpToolCall(mcpAllowedTool),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        200,
		Injected:      map[string]string{"Authorization": "Bearer " + mcpGitHubToken},
		Absent:        h.AlwaysAbsent(),
		UpstreamCalls: 1,
	})
}

// TestMCP_DeniedToolIsRefusedBeforeTheUpstream is the row the wiring exists for.
// The two requests differ only in a tool name buried in a JSON body: same mount,
// same role, same credential, same path, same capability. Nothing but the policy
// reading that body can tell them apart.
//
// The zero-upstream-calls assertion is the point. A denial that arrives after
// the request has been forwarded has already spent the credential on the call it
// was meant to prevent.
func TestMCP_DeniedToolIsRefusedBeforeTheUpstream(t *testing.T) {
	ensureEnv(t)

	status, body, respHeaders := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         mcpToolCall(mcpDeniedTool),
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})

	// A 403 alone would be satisfied by any layer refusing for any reason. The
	// challenge is what identifies the refusal as this filter's: it is the deny
	// surface the policy path emits, and nothing else in the chain produces it.
	if challenge := respHeaders.Get("WWW-Authenticate"); !strings.Contains(challenge, "insufficient_permissions") {
		t.Errorf("want the policy deny challenge, got WWW-Authenticate: %q", challenge)
	}
}

// TestMCP_MalformedBodyIsRefused checks that a truncated body is refused with
// nothing forwarded, and that the refusal comes from the filter.
//
// It used to answer 401. The agent's implicit login reused the caller's HTTP
// request and decoded its body while resolving the agent's identity, so a body
// the generic decoder could not read failed the login — telling the caller to
// renew a credential that was never the problem. The login no longer reads the
// caller's body, so the request authenticates and the strict JSON-RPC parser is
// what rejects it: a 403 carrying the policy deny challenge.
func TestMCP_MalformedBodyIsRefused(t *testing.T) {
	ensureEnv(t)

	status, body, respHeaders := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":`,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})

	// Without this the row would pass on any refusal for any reason, which is
	// exactly how it read as correct while answering 401.
	if challenge := respHeaders.Get("WWW-Authenticate"); !strings.Contains(challenge, "insufficient_permissions") {
		t.Errorf("want the policy deny challenge, got WWW-Authenticate: %q", challenge)
	}
}

// TestMCP_ValidJSONButInvalidJSONRPCIsDeniedByPolicy pins the same fail-closed
// property from the other side: a body that is well-formed JSON but not
// well-formed JSON-RPC. A duplicate key is what separates the two parsers —
// last-one-wins for a generic decoder, a refusal for the strict one.
//
// That is the property worth pinning: a body the filter cannot interpret is
// denied rather than waved through as "no rule matched", which is how a filter
// of this shape usually breaks. This row would pass differently with no MCP
// contract attached to the mount.
func TestMCP_ValidJSONButInvalidJSONRPCIsDeniedByPolicy(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/call"}`,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        403,
		UpstreamCalls: 0,
	})
}
