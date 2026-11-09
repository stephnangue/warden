//go:build e2e

package fullchain

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stephnangue/warden/audit"
	h "github.com/stephnangue/warden/e2e/helpers"
	"github.com/stephnangue/warden/logical"
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
	// This mount is about credential extraction, not authorization, so it wants
	// every call to reach the upstream. Since an MCP-enforcing mount now
	// refuses traffic with no contract in scope, "unrestricted" has to be said
	// out loud — which is the point: it stays visible in a policy listing.
	MCPPolicyRules: h.MCPUnrestricted,
}

// mcpNoContractEnv is an MCP mount with a capability grant and deliberately no
// tool contract. It exists to prove the absence deny end to end: the shape an
// operator lands in by granting a mount and forgetting the contract used to be
// indistinguishable from meaning "unrestricted".
var mcpNoContractEnv = h.ProviderEnv{
	Mount:      "fc-mcp-nocontract",
	Type:       "mcp",
	URLKey:     "mcp_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": mcpAPIKey},
}

// mcpBodyCapBytes is small enough that an ordinary tool catalog exceeds it, so
// a test can tell buffering from streaming. The default cap is 10MB, which no
// plausible fixture reaches — a listing sized against it would prove nothing.
const mcpBodyCapBytes = 65536

// mcpUnrestrictedSmallCapEnv pairs the wildcard contract with a deliberately
// tight max_body_size. Attaching a keep-everything filter makes the gateway
// buffer the whole upstream response against that cap and fail closed above it,
// so this mount is what separates "the filter was skipped" from "the filter ran
// and happened to keep everything" — two outcomes that are otherwise identical
// on the wire.
var mcpUnrestrictedSmallCapEnv = h.ProviderEnv{
	Mount:          "fc-mcp-bigcatalog",
	Type:           "mcp",
	URLKey:         "mcp_url",
	CredType:       "api_key",
	CredConfig:     map[string]string{"api_key": mcpAPIKey},
	MCPPolicyRules: h.MCPUnrestricted,
	ExtraConfig:    map[string]any{"max_body_size": mcpBodyCapBytes},
}

// mcpSkillsEnv governs the Skills extension. It needs a mount of its own:
// mcpEnv's contract allows only tools/*, so a skills call through it would be
// refused by the method gate, and a refusal row there would pass for the wrong
// reason. Here the methods are open and the resources family alone decides.
var mcpSkillsEnv = h.ProviderEnv{
	Mount:      "fc-mcp-skills",
	Type:       "mcp",
	URLKey:     "mcp_url",
	CredType:   "api_key",
	CredConfig: map[string]string{"api_key": mcpAPIKey},
	MCPPolicyRules: `  methods { allowed = ["skills/list", "skills/get", "resources/read", "resources/directory/read"] }
  resources { allowed = ["` + mcpAllowedSkill + `", "` + mcpAllowedSkill + `/*"] }`,
}

const (
	mcpAllowedSkill = "skill://fc-allowed-skill"
	mcpDeniedSkill  = "skill://fc-denied-skill"
)

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
// of this shape usually breaks.
//
// Note the status alone no longer distinguishes this from an ungoverned mount —
// both answer 403 with the same challenge. What makes this row specific is the
// contract being attached: the refusal comes from the body failing to parse
// against rules that exist, not from there being no rules.
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

// mcpMountGovernedBy brings up an MCP mount for one test, under rules.
func mcpMountGovernedBy(t *testing.T, mount, rules string) h.ProviderEnv {
	t.Helper()
	env := h.ProviderEnv{
		Mount:          mount,
		Type:           "mcp",
		URLKey:         "mcp_url",
		CredType:       "api_key",
		CredConfig:     map[string]string{"api_key": mcpAPIKey},
		MCPPolicyRules: rules,
	}
	mountEraProvider(t, env, upstream.URL)
	return env
}

// attachMCPContract writes a second MCP policy for env's gateway shapes, each
// followed by suffix, and adds it to the role the test calls under.
func attachMCPContract(t *testing.T, env h.ProviderEnv, name, suffix, rules string) {
	t.Helper()
	doc := fmt.Sprintf("path %q {\n%s\n}\npath %q {\n%s\n}\n",
		env.Mount+"/gateway"+suffix, rules, env.Mount+"/role/+/gateway"+suffix, rules)
	if status, body := h.APIRequest(t, "POST", "sys/policies/mcp/"+name, leaderPort, fmt.Sprintf(`{"policy":%q}`, doc)); status >= 300 {
		t.Fatalf("write mcp policy %s: %d: %s", name, status, body)
	}
	t.Cleanup(func() { h.APIRequest(t, "DELETE", "sys/policies/mcp/"+name, leaderPort, "") })
	h.WriteRoleInNS(t, leaderPort, "", env.CertRole(),
		h.Role{Policies: []string{env.Policy(), env.MCPPolicy(), name}, CredSpec: env.Spec()})
}

// callMCP sends one body to path under env's certificate role. An empty body
// is a body-less GET.
func callMCP(t *testing.T, env h.ProviderEnv, path, body string) (int, []byte) {
	t.Helper()
	upstream.Reset()
	status, resp, _ := h.ChainRequest(t, leaderPort, env, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         env.CertRole(),
		Path:         path,
		Body:         body,
	})
	return status, resp
}

// awaitMCPDecision waits for an audited MCP decision on env's mount that
// match accepts.
func awaitMCPDecision(t *testing.T, env h.ProviderEnv, match func(*logical.MCPDecision) bool) *logical.MCPDecision {
	t.Helper()
	entries := h.AwaitAuditEntries(t, h.NodeNumberForPort(leaderPort), env.Mount, 1, func(e audit.LogEntry) bool {
		return e.Auth != nil && e.Auth.PolicyResults != nil && e.Auth.PolicyResults.MCPDecision != nil &&
			match(e.Auth.PolicyResults.MCPDecision)
	})
	return entries[0].Auth.PolicyResults.MCPDecision
}

const mcpDeniesTheDeniedTool = `  tools { denied = ["` + mcpDeniedTool + `"] }`

// A denied list in one contract beats another contract's allow, and the call
// never reaches the upstream.
func TestMCP_DeniedListBeatsAnotherContractsAllow(t *testing.T) {
	ensureEnv(t)
	env := mcpMountGovernedBy(t, "fc-mcp-denied-final", h.MCPUnrestricted)
	const guard = "fc-mcp-denied-final-guard"
	attachMCPContract(t, env, guard, "*", mcpDeniesTheDeniedTool)

	status, body := callMCP(t, env, "", mcpToolCall(mcpDeniedTool))
	h.AssertChain(t, upstream, status, body, h.ChainWant{Status: 403, UpstreamCalls: 0})
	decision := awaitMCPDecision(t, env, func(d *logical.MCPDecision) bool { return d.Name == mcpDeniedTool })
	if decision.RuleType != "denied_tools" || decision.PolicyName != guard || decision.MatchedRule != mcpDeniedTool {
		t.Fatalf("audited decision = %+v, want denied_tools from %s", decision, guard)
	}

	status, body = callMCP(t, env, "", mcpToolCall(mcpAllowedTool))
	h.AssertChain(t, upstream, status, body, h.ChainWant{Status: 200, UpstreamCalls: 1})
}

// A narrower stanza with only denied lists adds its denials without hiding the
// broader contract's allows.
func TestMCP_NarrowDenyOnlyStanzaDoesNotShadowABroaderAllow(t *testing.T) {
	ensureEnv(t)
	env := mcpMountGovernedBy(t, "fc-mcp-denied-narrow", h.MCPUnrestricted)
	attachMCPContract(t, env, "fc-mcp-denied-narrow-guard", "/admin", mcpDeniesTheDeniedTool)

	status, body := callMCP(t, env, "admin", mcpToolCall(mcpAllowedTool))
	h.AssertChain(t, upstream, status, body, h.ChainWant{Status: 200, UpstreamCalls: 1})

	status, body = callMCP(t, env, "admin", mcpToolCall(mcpDeniedTool))
	h.AssertChain(t, upstream, status, body, h.ChainWant{Status: 403, UpstreamCalls: 0})

	status, body = callMCP(t, env, "other", mcpToolCall(mcpDeniedTool))
	h.AssertChain(t, upstream, status, body, h.ChainWant{Status: 200, UpstreamCalls: 1})
}

// Alone on a path, a stanza with only denied lists refuses what it names and
// says so, allows nothing else, and has no opinion on a body-less request.
func TestMCP_DenyOnlyStanzaIsNoContract(t *testing.T) {
	ensureEnv(t)
	env := mcpMountGovernedBy(t, "fc-mcp-deny-only", mcpDeniesTheDeniedTool)

	status, body := callMCP(t, env, "", mcpToolCall(mcpDeniedTool))
	h.AssertChain(t, upstream, status, body, h.ChainWant{Status: 403, UpstreamCalls: 0})
	decision := awaitMCPDecision(t, env, func(d *logical.MCPDecision) bool { return d.Name == mcpDeniedTool })
	if decision.RuleType != "denied_tools" || decision.PolicyName != env.MCPPolicy() {
		t.Fatalf("audited decision = %+v, want denied_tools from %s", decision, env.MCPPolicy())
	}

	status, body = callMCP(t, env, "", mcpToolCall(mcpAllowedTool))
	h.AssertChain(t, upstream, status, body, h.ChainWant{Status: 403, UpstreamCalls: 0})
	if !strings.Contains(string(body), "No MCP policy") {
		t.Errorf("body = %s, want the absence reason named", body)
	}
	awaitMCPDecision(t, env, func(d *logical.MCPDecision) bool { return d.RuleType == "no_mcp_policy" })

	status, body = callMCP(t, env, "", "")
	h.AssertChain(t, upstream, status, body, h.ChainWant{Status: 200, UpstreamCalls: 1})
}
