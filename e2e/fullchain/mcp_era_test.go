//go:build e2e

package fullchain

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	h "github.com/stephnangue/warden/e2e/helpers"
)

// Warden fronts MCP upstreams of two protocol eras at once, and every rule it
// gained for the 2026-07-28 revision came with a branch that does LESS for
// legacy traffic — skip the header requirements, keep accepting batches, admit
// the pre-modern handshake. Those branches are fail-open by shape: taking one
// by mistake means less enforcement, silently.
//
// So each is covered twice: once proving the branch is taken when it should
// be, and once proving it is NOT taken when it should not be. A suite that only
// exercised the permissive side would keep passing after the condition guarding
// it stopped working, which is the failure mode worth designing against.
//
// The era-pure upstreams are hand-rolled rather than SDK instances, and that is
// not incidental. An SDK server configured either way answers both eras: a
// stateful one still serves server/discover (explicitly exempted, so clients
// can learn supported protocols), and a stateless one still serves initialize
// with an ephemeral session. Neither would produce the refusal the off-diagonal
// cells exist to observe. The legacy client is likewise plain HTTP: a v1.7.0
// client always opens at the latest revision, and the option that would pin an
// older one is unexported.

const (
	mcpModernRevision = "2026-07-28"
	mcpLegacyRevision = "2025-11-25"
	eraTool           = "era_tool"
)

// mcpEraUpstream records what reached it and answers as one era only.
type mcpEraUpstream struct {
	*httptest.Server

	mu       sync.Mutex
	requests []mcpEraRequest
}

type mcpEraRequest struct {
	method       string // JSON-RPC method from the body
	headerMethod string
	version      string
	body         string
}

func (u *mcpEraUpstream) record(r mcpEraRequest) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests = append(u.requests, r)
}

func (u *mcpEraUpstream) seen() []mcpEraRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]mcpEraRequest, len(u.requests))
	copy(out, u.requests)
	return out
}

func (u *mcpEraUpstream) reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests = nil
}

// bodyMethod pulls the JSON-RPC method out of a single-call body. A batch or an
// unreadable body yields "", which no era-defining branch matches.
func bodyMethod(raw []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return ""
	}
	return env.Method
}

// startEraUpstream builds an upstream that serves exactly one protocol era and
// refuses the other era's entry point, the way a server of that vintage would.
func startEraUpstream(t *testing.T, modern bool) *mcpEraUpstream {
	t.Helper()
	up := &mcpEraUpstream{}

	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		method := bodyMethod(raw)

		up.record(mcpEraRequest{
			method:       method,
			headerMethod: r.Header.Get("Mcp-Method"),
			version:      r.Header.Get("MCP-Protocol-Version"),
			body:         string(raw),
		})

		// The era-defining refusal. A modern-only server has no initialize to
		// offer; a legacy-only one has never heard of server/discover.
		switch {
		case modern && method == "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"initialize is not supported at 2026-07-28"}}`)
			return
		case !modern && method == "server/discover":
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// cacheScope is what a shared intermediary reads to decide whether it
		// may serve these bytes to the next caller. "public" is the value
		// Warden has to narrow.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":%q}],"cacheScope":"public","ttlMs":60000}}`, eraTool)
	}))
	// Deliberately no t.Cleanup: these are built inside a sync.Once, so the t
	// in hand belongs to whichever test happened to run first. Closing on it
	// would tear both upstreams down after that one test and leave every later
	// row talking to a dead port — a 502 that looks like a Warden fault and is
	// not. The shared recording upstream skips cleanup for the same reason;
	// the listeners live as long as the test binary.
	return up
}

// eraEnv builds an MCP mount for one era's upstream. Each era needs its own
// mount because the upstream URL is mount config.
func eraEnv(mount string) h.ProviderEnv {
	return h.ProviderEnv{
		Mount:      mount,
		Type:       "mcp",
		URLKey:     "mcp_url",
		CredType:   "api_key",
		CredConfig: map[string]string{"api_key": mcpAPIKey},
		// Wide open on purpose: these rows are about era handling, and a narrow
		// contract would refuse calls before the era logic was reached. The
		// resources family is named so URI-bearing subscriptions have a grant
		// to answer to.
		MCPPolicyRules: `  methods   { allowed = ["*"] }
  tools     { allowed = ["*"] }
  prompts   { allowed = ["*"] }
  resources { allowed = ["repo://allowed/*"] }`,
	}
}

var (
	modernUpstream *mcpEraUpstream
	legacyUpstream *mcpEraUpstream
	modernEnv      = eraEnv("fc-mcp-modern")
	legacyEnv      = eraEnv("fc-mcp-legacy")
	eraOnce        sync.Once
	eraReady       bool
)

// ensureEraEnv mounts one MCP provider per era, each pointed at the matching
// hand-rolled upstream.
func ensureEraEnv(t *testing.T) {
	t.Helper()
	ensureEnv(t)
	eraOnce.Do(func() {
		modernUpstream = startEraUpstream(t, true)
		legacyUpstream = startEraUpstream(t, false)

		h.SetupFullChainProvider(t, leaderPort, modernUpstream.URL, modernEnv)
		h.SetupFullChainProvider(t, leaderPort, legacyUpstream.URL, legacyEnv)
		eraReady = true
	})
	if !eraReady {
		t.Fatal("dual-era MCP environment is not available")
	}
	modernUpstream.reset()
	legacyUpstream.reset()
}

// mountEraProvider brings up an extra mount for one test and tears it down
// after, for the rows that need a contract other than the wide-open default.
func mountEraProvider(t *testing.T, env h.ProviderEnv, upstreamURL string) {
	t.Helper()
	h.SetupFullChainProvider(t, leaderPort, upstreamURL, env)
	t.Cleanup(func() { h.TeardownFullChainProviderBestEffort(leaderPort, env) })
}

// eraCall drives one JSON-RPC body through a mount with the given transport
// headers, as a client of whichever era those headers describe.
func eraCall(t *testing.T, env h.ProviderEnv, body string, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	return h.ChainRequest(t, leaderPort, env, h.ChainOpts{
		AgentCertPEM: agentCert(t),
		Bearer:       h.FullChainUserJWT(t),
		Role:         env.CertRole(),
		Body:         body,
		Headers:      headers,
	})
}

// modernHeaders is what a 2026-07-28 client sends: its revision, a duplicate of
// the method it is calling, and — for the three name-bearing methods — the name
// it is calling it on. Omitting the name on one of those is an absence the
// modern era is held to, which TestMCPEra_ModernClientMustSendTheHeaders covers
// deliberately; every other row wants a conforming client.
func modernHeaders(method string, name ...string) map[string]string {
	hdr := map[string]string{
		"MCP-Protocol-Version": mcpModernRevision,
		"Mcp-Method":           method,
	}
	if len(name) > 0 {
		hdr["Mcp-Name"] = name[0]
	}
	return hdr
}

func jsonRPC(method string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `"}`
}

// =============================================================================
// The era matrix
// =============================================================================

// Modern client, modern upstream. server/discover is the first request a
// v1.7.0 client sends on every connection, so this diagonal has to work before
// anything else does.
func TestMCPEra_ModernClientModernUpstream(t *testing.T) {
	ensureEraEnv(t)

	status, _, _ := eraCall(t, modernEnv, jsonRPC("server/discover"), modernHeaders("server/discover"))
	if status != 200 {
		t.Fatalf("server/discover = %d, want 200", status)
	}

	status, _, _ = eraCall(t, modernEnv, mcpToolCall(eraTool), modernHeaders("tools/call", eraTool))
	if status != 200 {
		t.Fatalf("tools/call after discover = %d, want 200", status)
	}

	seen := modernUpstream.seen()
	if len(seen) != 2 {
		t.Fatalf("upstream saw %d requests, want 2", len(seen))
	}
	if seen[0].method != "server/discover" {
		t.Errorf("first upstream call = %q, want server/discover", seen[0].method)
	}
}

// Legacy client, legacy upstream: the path that works today and must not
// regress. No version header, no transport headers, initialize as the opener.
func TestMCPEra_LegacyClientLegacyUpstream(t *testing.T) {
	ensureEraEnv(t)

	status, _, _ := eraCall(t, legacyEnv, jsonRPC("initialize"), nil)
	if status != 200 {
		t.Fatalf("initialize = %d, want 200 — the legacy handshake must keep working", status)
	}

	status, _, _ = eraCall(t, legacyEnv, mcpToolCall(eraTool), nil)
	if status != 200 {
		t.Fatalf("tools/call = %d, want 200", status)
	}
}

// Modern client, legacy upstream. Warden must pass server/discover through —
// it is exempt from the method gate — and the upstream's 404 must reach the
// client intact, so its SDK can fall back to initialize, which is exempt too.
// A Warden that refused either would strand the client with no way in.
func TestMCPEra_ModernClientLegacyUpstream(t *testing.T) {
	ensureEraEnv(t)

	status, _, _ := eraCall(t, legacyEnv, jsonRPC("server/discover"), modernHeaders("server/discover"))
	if status != 404 {
		t.Fatalf("server/discover against a legacy upstream = %d, want the upstream's own 404", status)
	}
	if seen := legacyUpstream.seen(); len(seen) != 1 || seen[0].method != "server/discover" {
		t.Fatalf("Warden must forward server/discover rather than refuse it; upstream saw %+v", seen)
	}

	// The fallback a client makes on seeing that 404.
	status, _, _ = eraCall(t, legacyEnv, jsonRPC("initialize"),
		map[string]string{"MCP-Protocol-Version": mcpLegacyRevision, "Mcp-Method": "initialize"})
	if status != 200 {
		t.Fatalf("initialize fallback = %d, want 200", status)
	}
}

// Legacy client, modern upstream. Warden lets initialize through — it is
// exempt — and the upstream refuses it on its own terms. The point of the row
// is that the failure is legible: a JSON-RPC error the client can read, not a
// hang, and not a Warden-shaped denial that would send it looking at policy.
func TestMCPEra_LegacyClientModernUpstream(t *testing.T) {
	ensureEraEnv(t)

	status, body, _ := eraCall(t, modernEnv, jsonRPC("initialize"), nil)
	if status != 400 {
		t.Fatalf("initialize against a modern upstream = %d, want the upstream's own 400", status)
	}
	if !strings.Contains(string(body), "-32601") {
		t.Errorf("body = %s, want the upstream's JSON-RPC error to reach the client verbatim", body)
	}
	if seen := modernUpstream.seen(); len(seen) != 1 {
		t.Fatalf("Warden must forward initialize rather than refuse it; upstream saw %d requests", len(seen))
	}
}

// =============================================================================
// server/discover exemption
// =============================================================================

// Exempt from the method gate, so a contract that allow-lists only data-plane
// methods still admits it.
func TestMCPEra_ServerDiscoverNeedsNoAllowListEntry(t *testing.T) {
	ensureEraEnv(t)

	narrow := eraEnv("fc-mcp-discover-narrow")
	narrow.MCPPolicyRules = `  methods { allowed = ["tools/list"] }
  tools   { allowed = ["*"] }`
	mountEraProvider(t, narrow, modernUpstream.URL)

	status, _, _ := eraCall(t, narrow, jsonRPC("server/discover"), modernHeaders("server/discover"))
	if status != 200 {
		t.Fatalf("server/discover under a narrow contract = %d, want 200", status)
	}
}

// The exemption rescues it from deny-by-default and nothing more: naming it in
// denied_methods still blocks it, because the deny gate runs first.
func TestMCPEra_ServerDiscoverExplicitDenyStillBlocks(t *testing.T) {
	ensureEraEnv(t)

	denied := eraEnv("fc-mcp-discover-denied")
	denied.MCPPolicyRules = `  methods {
    allowed = ["*"]
    denied  = ["server/discover"]
  }
  tools { allowed = ["*"] }`
	mountEraProvider(t, denied, modernUpstream.URL)
	modernUpstream.reset()

	status, _, _ := eraCall(t, denied, jsonRPC("server/discover"), modernHeaders("server/discover"))
	if status != 403 {
		t.Fatalf("explicitly denied server/discover = %d, want 403", status)
	}
	if n := len(modernUpstream.seen()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0 — a denied call must not be forwarded", n)
	}
}

// A capability grant with no contract refuses it like everything else.
// Exempting lifecycle methods from the absence rule would let a caller holding
// no contract probe which mounts exist by watching which ones answer.
func TestMCPEra_ServerDiscoverRefusedWithNoContract(t *testing.T) {
	ensureEraEnv(t)

	bare := eraEnv("fc-mcp-discover-nocontract")
	bare.MCPPolicyRules = "" // no contract at all
	mountEraProvider(t, bare, modernUpstream.URL)
	modernUpstream.reset()

	status, body, _ := eraCall(t, bare, jsonRPC("server/discover"), modernHeaders("server/discover"))
	if status != 403 {
		t.Fatalf("server/discover with no contract = %d, want 403", status)
	}
	if !strings.Contains(string(body), "No MCP policy") {
		t.Errorf("body = %s, want the absence reason named", body)
	}
	if n := len(modernUpstream.seen()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

// =============================================================================
// Transport-header validation, and both of its era branches
// =============================================================================

// A modern client whose Mcp-Method contradicts its body is refused in the
// protocol's own terms — a JSON-RPC -32020 with the id echoed, not the 403 a
// policy denial gets. The distinction is what stops a dual-era client reading
// the refusal as "not permitted" and downgrading to initialize instead of
// correcting its headers.
func TestMCPEra_HeaderMismatchIsAProtocolError(t *testing.T) {
	ensureEraEnv(t)

	status, body, _ := eraCall(t, modernEnv, mcpToolCall(eraTool), map[string]string{
		"MCP-Protocol-Version": mcpModernRevision,
		"Mcp-Method":           "tools/list", // the body says tools/call
		"Mcp-Name":             eraTool,
	})

	if status != 400 {
		t.Fatalf("header mismatch = %d, want 400", status)
	}
	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("body is not a JSON-RPC envelope: %s", body)
	}
	if resp.Error.Code != -32020 {
		t.Errorf("error.code = %d, want -32020", resp.Error.Code)
	}
	if resp.ID != 1 {
		t.Errorf("id = %d, want the request id echoed", resp.ID)
	}
	if n := len(modernUpstream.seen()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

// The first fail-open branch, and the row that fails if it is taken wrongly: a
// client sending no version header is not required to send the transport
// headers — but one it does send must still describe its body. Skipping the
// match for a version-less client would make the whole check bypassable by
// omission.
func TestMCPEra_MismatchWithoutVersionHeaderStillDenied(t *testing.T) {
	ensureEraEnv(t)

	status, _, _ := eraCall(t, legacyEnv, mcpToolCall(eraTool), map[string]string{
		"Mcp-Method": "tools/list", // no version header, contradictory method
	})
	if status != 400 {
		t.Fatalf("mismatched header from a version-less client = %d, want 400", status)
	}
	if n := len(legacyUpstream.seen()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

// The other half of that branch: a legacy client sending no transport headers
// at all is required to send none, and passes.
func TestMCPEra_LegacyClientWithoutHeadersPasses(t *testing.T) {
	ensureEraEnv(t)

	status, _, _ := eraCall(t, legacyEnv, mcpToolCall(eraTool), nil)
	if status != 200 {
		t.Fatalf("legacy client with no transport headers = %d, want 200", status)
	}
}

// A modern client must send what its revision requires. Omitting Mcp-Method is
// an absence rather than a mismatch, and only the modern era is held to it —
// the row above proves the legacy era is not.
func TestMCPEra_ModernClientMustSendTheHeaders(t *testing.T) {
	ensureEraEnv(t)

	status, _, _ := eraCall(t, modernEnv, mcpToolCall(eraTool), map[string]string{
		"MCP-Protocol-Version": mcpModernRevision,
	})
	if status != 400 {
		t.Fatalf("modern client omitting Mcp-Method = %d, want 400", status)
	}
}

// =============================================================================
// Batches: refused for the modern era, still served for the legacy one
// =============================================================================

func TestMCPEra_ModernBatchRefused(t *testing.T) {
	ensureEraEnv(t)

	batch := `[` + mcpToolCallID(eraTool, 1) + `,` + mcpToolCallID(eraTool, 2) + `]`
	status, _, _ := eraCall(t, modernEnv, batch, map[string]string{
		"MCP-Protocol-Version": mcpModernRevision,
	})

	if status != 403 {
		t.Fatalf("modern batch = %d, want 403", status)
	}
	if n := len(modernUpstream.seen()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

// The fail-open branch that keeps dual-era support real. A legacy client's
// batch is still accepted, still policy-checked, and still arrives whole.
func TestMCPEra_LegacyBatchStillServed(t *testing.T) {
	ensureEraEnv(t)

	batch := `[` + mcpToolCallID(eraTool, 1) + `,` + mcpToolCallID(eraTool, 2) + `]`
	status, _, _ := eraCall(t, legacyEnv, batch, nil)

	if status != 200 {
		t.Fatalf("legacy batch = %d, want 200", status)
	}
	seen := legacyUpstream.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(seen))
	}
	if !strings.HasPrefix(strings.TrimSpace(seen[0].body), "[") {
		t.Errorf("upstream body = %s, want the batch to arrive as an array", seen[0].body)
	}
}

// Accepting batches is not exempting them from the contract: one denied
// element refuses the whole body.
func TestMCPEra_LegacyBatchStillPolicyChecked(t *testing.T) {
	ensureEraEnv(t)

	narrow := eraEnv("fc-mcp-batch-narrow")
	narrow.MCPPolicyRules = `  methods { allowed = ["tools/call"] }
  tools   { allowed = ["` + eraTool + `"] }`
	mountEraProvider(t, narrow, legacyUpstream.URL)
	legacyUpstream.reset()

	batch := `[` + mcpToolCallID(eraTool, 1) + `,` + mcpToolCallID("not_allowed", 2) + `]`
	status, _, _ := eraCall(t, narrow, batch, nil)

	if status != 403 {
		t.Fatalf("legacy batch with a denied element = %d, want 403", status)
	}
	if n := len(legacyUpstream.seen()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0 — one denied element refuses the batch", n)
	}
}

// =============================================================================
// Resource subscriptions
// =============================================================================

func listenBody(uris ...string) string {
	quoted := make([]string, len(uris))
	for i, u := range uris {
		quoted[i] = `"` + u + `"`
	}
	return `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"resourceSubscriptions":[` +
		strings.Join(quoted, ",") + `]}}}`
}

// Subscribing to a resource's update stream answers to the same grant that
// governs reading it: the content never arrives, but its existence and the
// timing of every change do.
func TestMCPEra_ListenURIAnswersToTheResourcesFamily(t *testing.T) {
	ensureEraEnv(t)

	status, _, _ := eraCall(t, modernEnv, listenBody("repo://allowed/api"),
		modernHeaders("subscriptions/listen"))
	if status != 200 {
		t.Fatalf("allowed subscription URI = %d, want 200", status)
	}

	modernUpstream.reset()
	status, _, _ = eraCall(t, modernEnv, listenBody("repo://allowed/api", "repo://secret/keys"),
		modernHeaders("subscriptions/listen"))
	if status != 403 {
		t.Fatalf("subscription to an ungranted URI = %d, want 403", status)
	}
	if n := len(modernUpstream.seen()); n != 0 {
		t.Errorf("upstream saw %d requests, want 0", n)
	}
}

// A listen that names no resource carries no resource access, so it passes
// under a contract with no resources block at all — while one that names a URI
// is refused by the same contract, deny-by-default being what a missing block
// means.
func TestMCPEra_ListChangedOnlyListenNeedsNoResourceGrant(t *testing.T) {
	ensureEraEnv(t)

	noResources := eraEnv("fc-mcp-listen-noresources")
	noResources.MCPPolicyRules = `  methods { allowed = ["subscriptions/listen"] }`
	mountEraProvider(t, noResources, modernUpstream.URL)

	body := `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true}}}`
	status, _, _ := eraCall(t, noResources, body, modernHeaders("subscriptions/listen"))
	if status != 200 {
		t.Fatalf("list-changed-only listen = %d, want 200", status)
	}

	status, _, _ = eraCall(t, noResources, listenBody("repo://allowed/api"),
		modernHeaders("subscriptions/listen"))
	if status != 403 {
		t.Fatalf("URI-bearing listen with no resources block = %d, want 403", status)
	}
}

// =============================================================================
// Cache hygiene
// =============================================================================

// A listing pruned for one principal is not the document another would get, so
// neither the body's cacheScope nor the absence of a Cache-Control header may
// leave a shared cache free to serve it onward.
func TestMCPEra_FilteredListingIsMarkedPrivate(t *testing.T) {
	ensureEraEnv(t)

	pruning := eraEnv("fc-mcp-cache-pruning")
	// The upstream advertises era_tool; this contract allows a different one,
	// so the listing is pruned and the body rewritten.
	pruning.MCPPolicyRules = `  methods { allowed = ["tools/list"] }
  tools   { allowed = ["some_other_tool"] }`
	mountEraProvider(t, pruning, modernUpstream.URL)

	status, body, hdr := eraCall(t, pruning, jsonRPC("tools/list"), modernHeaders("tools/list"))
	if status != 200 {
		t.Fatalf("tools/list = %d, want 200", status)
	}
	if got := hdr.Get("Cache-Control"); !strings.Contains(got, "private") {
		t.Errorf("Cache-Control = %q, want it to carry private", got)
	}
	if strings.Contains(string(body), `"public"`) {
		t.Errorf("body still advertises a public cacheScope: %s", body)
	}
	if !strings.Contains(string(body), `"private"`) {
		t.Errorf("body = %s, want cacheScope narrowed to private", body)
	}
	if strings.Contains(string(body), eraTool) {
		t.Errorf("body = %s, want the denied tool pruned", body)
	}
}

// The fast path: a wildcard contract keeps every item, so no filter runs and
// the body is never rewritten — but the response still varies by principal,
// and the header still has to say so.
func TestMCPEra_UnfilteredListingIsStillMarkedPrivate(t *testing.T) {
	ensureEraEnv(t)

	status, body, hdr := eraCall(t, modernEnv, jsonRPC("tools/list"), modernHeaders("tools/list"))
	if status != 200 {
		t.Fatalf("tools/list = %d, want 200", status)
	}
	if got := hdr.Get("Cache-Control"); !strings.Contains(got, "private") {
		t.Errorf("Cache-Control = %q, want private on the keep-everything path too", got)
	}
	if !strings.Contains(string(body), eraTool) {
		t.Errorf("body = %s, want the allowed tool kept", body)
	}
}
