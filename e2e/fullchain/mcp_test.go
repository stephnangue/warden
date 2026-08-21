//go:build e2e

package fullchain

import (
	"strings"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// mcp is the only provider whose authorization depends on the request *body*.
// Everything else in this suite is decided by path and capability; here a policy
// names the tools a caller may invoke, and the decision needs the JSON-RPC call
// itself.
//
// The decision logic is covered thoroughly in-process — core has seven files on
// mcp { } parsing, evaluation and list filtering. What none of them exercise is
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
	// enforcement; without an mcp { } block the body is never inspected and
	// every JSON-RPC call the capability allows would go through.
	ExtraPolicyRules: `  mcp {
    allowed_methods = ["tools/call", "tools/list"]
    allowed_tools   = ["` + mcpAllowedTool + `"]
  }`,
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
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `"}}`
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
// nothing forwarded. It does NOT test the mcp { } filter, despite the shape:
// the request never reaches policy evaluation, because the body is unmarshalled
// into a map while the agent is still being authenticated, and a truncated body
// fails that decode first. The same request would 401 with no mcp { } block at
// all.
//
// What it is worth having as a row: refusal reaches the caller with nothing
// proxied, which is the property that must survive whatever happens to the
// authorization path. The status is the generic 401 of a failed agent login, not
// the 403 the filter returns. That early decode into a map is also why a valid
// JSON-RPC batch cannot be proxied at all: a top-level JSON array does not fit
// the shape, so it fails the same way before policy is ever consulted.
func TestMCP_MalformedBodyIsRefused(t *testing.T) {
	ensureEnv(t)

	status, body, _ := h.ChainRequest(t, leaderPort, mcpEnv, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         mcpEnv.CertRole(),
		Body:         `{"jsonrpc":"2.0","id":1,"method":`,
	})

	h.AssertChain(t, upstream, status, body, h.ChainWant{
		Status:        401,
		UpstreamCalls: 0,
	})
}

// TestMCP_ValidJSONButInvalidJSONRPCIsDeniedByPolicy is the fail-closed row the
// truncated-body case cannot be. A duplicate key is accepted by the generic
// decoder — last one wins — so the request survives authentication and reaches
// the filter, where the strict JSON-RPC parser rejects it.
//
// That is the property worth pinning: a body the filter cannot interpret is
// denied rather than waved through as "no rule matched", which is how a filter
// of this shape usually breaks. Unlike the truncated body, this row would pass
// differently with the mcp { } block removed.
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
