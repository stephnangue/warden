//go:build e2e

package helpers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stephnangue/warden/audit"
)

// auditResponseEntry is the entry an audited request emits once it has been
// fully processed — the point at which every principal is stamped.
const auditResponseEntry = string(audit.EntryTypeResponse)

// --- Full-chain provider test environment ---
//
// A gateway request crosses six layers: the provider's token extractor splits
// the inbound headers into an agent and a user principal, core resolves a role
// and evaluates policy, the credential engine mints, and the provider's
// credential extractor turns that mint into upstream auth headers. Each end is
// per-provider; neither can be checked in isolation, because the extractor's
// output is what the mint operates on and the mint's output is what the
// credential extractor operates on.
//
// What makes the whole chain observable is a recording upstream: it is the only
// place that can prove what Warden actually forwarded, as opposed to what it
// accepted. A response status says a request was authorized; only the recorded
// headers say the minted credential went out and the caller's own did not.
//
// Providers are set up individually against one shared pair of auth mounts.
// Splitting it that way matters because auth/cert is global — its trusted CA is
// a single stored value — so a per-provider SetupCertAuth would have each mount
// silently invalidate the certificates minted for the last one.

const (
	// FullChainUserAuthMount authenticates USER credentials for every full-chain
	// mount. Held apart from the userleg and githttp suites' mounts so the three
	// cannot leave state for each other.
	FullChainUserAuthMount = "auth/fullchain-user-jwt/"

	// FullChainUserAuthRole is the role user credentials are validated under.
	FullChainUserAuthRole = "e2e-fullchain-user"

	// FullChainAgentCN is the common name on agent certificates. It must match
	// the allowed_common_names pattern every full-chain cert role is created
	// with.
	FullChainAgentCN = "agent-fullchain"
)

// ProviderEnv describes one provider mount under test: where its upstream is,
// what credential it mints, and which header the mint is expected to land in.
//
// The two extractor axes are both parameters here. Inbound behaviour is
// determined by Type (each provider's token extractor is compiled in), and
// outbound behaviour by CredType plus CredConfig, which together decide what the
// credential extractor is handed.
type ProviderEnv struct {
	// Mount is the provider mount path. Prefix it so a full-chain mount can
	// never collide with one another suite owns.
	Mount string

	// Type is the provider type, e.g. "openai".
	Type string

	// URLKey is the config key carrying the upstream base URL, e.g.
	// "openai_url". Every httpproxy provider declares exactly one.
	URLKey string

	// ExtraConfig is merged into the mount config write. Values are emitted as
	// JSON, so booleans and numbers keep their types.
	ExtraConfig map[string]any

	// CredType is the credential type the spec mints, e.g. "api_key".
	CredType string

	// SourceType is the credential source backing the mount. Defaults to
	// "local", which holds the credential statically and calls nothing.
	//
	// Credential types are validated against their source, and only api_key,
	// github_token, aws_access_keys, cloudflare_keys and scaleway_keys accept a
	// local one — so any other type needs a source that will have it. Pick one
	// whose mint path can be satisfied without a real upstream.
	SourceType string

	// SourceConfig is the source's own configuration, needed when SourceType is
	// not "local".
	SourceConfig map[string]string

	// SourceRotationPeriod is emitted as rotation_period, in seconds. Zero omits
	// the field, which is what every static source wants. Some source types
	// refuse to exist without one, so it is not optional for them — and a source
	// that carries a period really does rotate, so keep it long enough that the
	// package's shared environment never rotates out from under an unrelated
	// test. A test that means to observe a rotation brings its own source.
	SourceRotationPeriod int

	// ExtraPolicyRules are appended inside the mount's gateway path stanza,
	// for providers whose authorization is finer-grained than a capability —
	// a body-authoritative rule set, say, which cannot be expressed as one.
	ExtraPolicyRules string

	// CredConfig is the spec config. For a local source these values are copied
	// verbatim into the minted credential, which is what lets a test assert on
	// an exact upstream header value.
	CredConfig map[string]string

	// Variants are additional credential specs on the same mount, each with its
	// own cert role. A credential extractor with optional fields has several
	// positive branches, and a role binds exactly one spec — so covering them
	// means several specs, but not several mounts. Keyed by variant name.
	//
	// "denied" is reserved: it would produce the same role name as DenyRole and
	// fail setup with a confusing 409. SetupFullChainProvider rejects it.
	Variants map[string]map[string]string
}

// CertRole is the cert-auth role the agent authenticates under.
func (p ProviderEnv) CertRole() string { return p.Mount + "-agent" }

// Policy is the CBP policy granting gateway access to the mount.
func (p ProviderEnv) Policy() string { return p.Mount + "-access" }

// Source is the credential source backing the mount.
func (p ProviderEnv) Source() string { return p.Mount + "-src" }

// Spec is the credential spec the cert role mints from.
func (p ProviderEnv) Spec() string { return p.Mount + "-cred" }

// VariantSpec is the credential spec for a named variant.
func (p ProviderEnv) VariantSpec(name string) string { return p.Mount + "-cred-" + name }

// VariantRole is the cert role bound to a named variant's spec. Pass it as
// ChainOpts.Role to select that variant.
func (p ProviderEnv) VariantRole(name string) string { return p.Mount + "-agent-" + name }

// DenyRole authenticates the same certificate but carries a policy with no
// gateway capability, so a request under it must be refused before it is
// forwarded. Pass it as ChainOpts.Role.
func (p ProviderEnv) DenyRole() string { return p.Mount + "-agent-denied" }

// DenyPolicy is the policy DenyRole carries.
func (p ProviderEnv) DenyPolicy() string { return p.Mount + "-denied" }

// JWTAgentRole authenticates the agent by bearer token instead of certificate.
// Needed for every shape where the agent arrives in a header — the dedicated
// agent channel, or a provider's own native channel — because those carry a
// token, and a mount whose agent leg is auth/cert cannot validate one.
func (p ProviderEnv) JWTAgentRole() string { return p.Mount + "-jwt-agent" }

// UpstreamRequest is one request the recording upstream received.
type UpstreamRequest struct {
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	// Body is what the upstream was sent, byte for byte. Warden buffers and
	// re-serves the request body on the way through, so this is the only place
	// from which "the caller's body survived that round trip" can be checked.
	Body []byte
}

// RecordingUpstream stands in for a provider's real API. It keeps what it was
// sent, which is the only vantage point from which "the minted credential went
// out and the caller's did not" can be checked, and by default answers a canned
// 200.
//
// A test that cares about the response half of the chain can replace the handler
// with SetHandler — streaming, in particular, cannot be observed through a
// buffered canned reply.
type RecordingUpstream struct {
	URL string

	server  *httptest.Server
	mu      sync.Mutex
	reqs    []UpstreamRequest
	handler http.HandlerFunc
}

// SetHandler replaces what the upstream returns, for the remainder of the test
// that sets it. Requests are still recorded. Passing nil restores the default.
//
// Registered as a cleanup rather than left in place: the upstream is shared by
// the whole package, so a handler that outlived its test would silently change
// what every later row is proxying.
func (u *RecordingUpstream) SetHandler(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	u.mu.Lock()
	u.handler = h
	u.mu.Unlock()
	t.Cleanup(func() {
		u.mu.Lock()
		u.handler = nil
		u.mu.Unlock()
	})
}

// StartRecordingUpstream starts the upstream. The caller owns its lifetime via
// Close: mounts are configured with its URL once for the whole package, so
// binding it to the first test's cleanup would leave every later test pointed at
// a closed listener.
func StartRecordingUpstream(t *testing.T) *RecordingUpstream {
	t.Helper()
	u := &RecordingUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Buffer the body to record it, then put it back: a handler installed by
		// SetHandler reads the same request, and it must not find it drained.
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))

		u.mu.Lock()
		u.reqs = append(u.reqs, UpstreamRequest{
			Method:   r.Method,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Header:   r.Header.Clone(),
			Body:     body,
		})
		custom := u.handler
		u.mu.Unlock()

		if custom != nil {
			custom(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	u.URL = u.server.URL
	return u
}

// Close stops the upstream.
func (u *RecordingUpstream) Close() {
	if u.server != nil {
		u.server.Close()
	}
}

// Requests returns every request received so far.
func (u *RecordingUpstream) Requests() []UpstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]UpstreamRequest(nil), u.reqs...)
}

// Last returns the most recent request. Fails the test if there was none.
//
// Most rows go through AssertChain, which inspects the last request itself. This
// is for the streaming rows, where the response has to be read before the
// exchange is complete, so the request cannot be asserted in the same breath as
// the status.
func (u *RecordingUpstream) Last(t *testing.T) UpstreamRequest {
	t.Helper()
	reqs := u.Requests()
	if len(reqs) == 0 {
		t.Fatal("upstream received no requests")
	}
	return reqs[len(reqs)-1]
}

// Reset clears the recorded requests so one test's traffic cannot be read as
// another's.
func (u *RecordingUpstream) Reset() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reqs = nil
}

// SetupFullChainCommon mounts the auth methods every full-chain provider shares:
// certificates for the agent leg, and a JWT mount for the user leg. Returns the
// CA for minting agent certificates.
//
// Call once per package. auth/cert stores a single trusted CA, so calling it
// again mid-run would invalidate every certificate already minted.
func SetupFullChainCommon(t *testing.T, port int) (caCertPEM string, caKey *ecdsa.PrivateKey) {
	t.Helper()

	// A previous run that failed mid-setup leaves mounts behind, and every later
	// attempt would then fail with 409 — turning one real failure into a cascade
	// that hides it.
	TeardownFullChainCommonBestEffort(port)

	// Unmounting an auth method and remounting it in the same breath races the
	// auth table update, which answers 500. SetupCertAuth fatals on that, and
	// because this runs under the package's sync.Once every later test then
	// fails instantly with "environment is not available" — one transient
	// conflict presenting as the whole suite collapsing.
	time.Sleep(time.Second)

	caCertPEM, caKey = SetupCertAuth(t, port)

	mustAPI(t, port, "POST", "sys/auth/fullchain-user-jwt", `{"type":"jwt"}`, "mount fullchain-user-jwt auth")
	time.Sleep(time.Second)

	mustAPI(t, port, "PUT", "auth/fullchain-user-jwt/config",
		fmt.Sprintf(`{"mode":"oidc","oidc_discovery_url":%q,"bound_issuer":%q}`, HydraIssuer, HydraIssuer),
		"configure fullchain-user-jwt auth")

	mustAPI(t, port, "POST", "auth/fullchain-user-jwt/role/"+FullChainUserAuthRole,
		`{"user_claim":"sub","token_ttl":3600}`, "create fullchain user role")

	return caCertPEM, caKey
}

// SetupFullChainProvider builds one provider mount pointed at upstreamURL, with
// a local credential source so the mint needs no upstream of its own, and a cert
// role bound to the resulting spec.
func SetupFullChainProvider(t *testing.T, port int, upstreamURL string, p ProviderEnv) {
	t.Helper()

	TeardownFullChainProviderBestEffort(port, p)

	mustAPI(t, port, "POST", "sys/providers/"+p.Mount,
		fmt.Sprintf(`{"type":%q,"description":"e2e full-chain %s"}`, p.Type, p.Type),
		"mount "+p.Type+" provider")
	time.Sleep(time.Second)

	// tls_skip_verify is what permits the http:// scheme on the upstream URL —
	// without it the config write is rejected outright, whatever the URL points
	// at.
	cfg := map[string]any{
		p.URLKey:          upstreamURL,
		"tls_skip_verify": true,
		"auto_auth_path":  "auth/cert/",
		"user_auth_path":  FullChainUserAuthMount,
		"user_auth_role":  FullChainUserAuthRole,
	}
	for k, v := range p.ExtraConfig {
		cfg[k] = v
	}
	mustAPI(t, port, "PUT", p.Mount+"/config", mustJSON(t, cfg), "configure "+p.Type+" provider")

	sourceType := p.SourceType
	if sourceType == "" {
		sourceType = "local"
	}
	source := map[string]any{"type": sourceType}
	if len(p.SourceConfig) > 0 {
		source["config"] = p.SourceConfig
	}
	if p.SourceRotationPeriod > 0 {
		source["rotation_period"] = p.SourceRotationPeriod
	}
	mustAPI(t, port, "POST", "sys/cred/sources/"+p.Source(),
		mustJSON(t, source), "create credential source for "+p.Mount)

	mustAPI(t, port, "POST", "sys/cred/specs/"+p.Spec(),
		mustJSON(t, map[string]any{
			"type":   p.CredType,
			"source": p.Source(),
			"config": p.CredConfig,
		}),
		"create credential spec for "+p.Mount)

	mustAPI(t, port, "POST", "sys/policies/cbp/"+p.Policy(),
		mustJSON(t, map[string]any{"policy": gatewayPolicy(p.Mount, p.ExtraPolicyRules)}),
		"create policy for "+p.Mount)

	mustAPI(t, port, "POST", "auth/cert/role/"+p.CertRole(),
		mustJSON(t, map[string]any{
			"allowed_common_names": []string{FullChainAgentCN},
			"token_policies":       []string{p.Policy()},
			"cred_spec_name":       p.Spec(),
			"token_ttl":            3600,
		}),
		"create cert role for "+p.Mount)

	// The denial counterpart: same certificate, same credential spec, a policy
	// that grants an unrelated path. Authentication therefore succeeds and only
	// authorization fails, which is the case worth asserting — a request refused
	// because it could not authenticate proves nothing about policy.
	mustAPI(t, port, "POST", "sys/policies/cbp/"+p.DenyPolicy(),
		mustJSON(t, map[string]any{
			"policy": "path \"sys/health\" {\n  capabilities = [\"read\"]\n}",
		}),
		"create deny policy for "+p.Mount)

	mustAPI(t, port, "POST", "auth/cert/role/"+p.DenyRole(),
		mustJSON(t, map[string]any{
			"allowed_common_names": []string{FullChainAgentCN},
			"token_policies":       []string{p.DenyPolicy()},
			"cred_spec_name":       p.Spec(),
			"token_ttl":            3600,
		}),
		"create deny cert role for "+p.Mount)

	// The bearer-agent counterpart. Recreated rather than created, because
	// auth/jwt/ is set up by the suite as a whole and survives our teardown.
	APIRequest(t, "DELETE", "auth/jwt/role/"+p.JWTAgentRole(), port, "")
	mustAPI(t, port, "POST", "auth/jwt/role/"+p.JWTAgentRole(),
		mustJSON(t, map[string]any{
			"token_policies": []string{p.Policy()},
			"cred_spec_name": p.Spec(),
			"user_claim":     "sub",
			"token_ttl":      3600,
		}),
		"create jwt agent role for "+p.Mount)

	for name, cfg := range p.Variants {
		if p.VariantRole(name) == p.DenyRole() {
			t.Fatalf("provider %s: variant %q collides with the built-in deny role", p.Mount, name)
		}
		mustAPI(t, port, "POST", "sys/cred/specs/"+p.VariantSpec(name),
			mustJSON(t, map[string]any{
				"type":   p.CredType,
				"source": p.Source(),
				"config": cfg,
			}),
			"create credential spec "+name+" for "+p.Mount)

		mustAPI(t, port, "POST", "auth/cert/role/"+p.VariantRole(name),
			mustJSON(t, map[string]any{
				"allowed_common_names": []string{FullChainAgentCN},
				"token_policies":       []string{p.Policy()},
				"cred_spec_name":       p.VariantSpec(name),
				"token_ttl":            3600,
			}),
			"create cert role "+name+" for "+p.Mount)
	}
}

// gatewayPolicy grants both gateway shapes: the bare one, used when the role
// arrives in a header, and the role-in-path one. extraRules is appended inside
// each stanza, so a provider's finer-grained rules apply however the role was
// selected.
func gatewayPolicy(mount, extraRules string) string {
	stanza := func(path string) string {
		body := "  capabilities = [\"read\",\"create\",\"update\",\"delete\",\"list\"]\n"
		if extraRules != "" {
			body += extraRules + "\n"
		}
		return fmt.Sprintf("path %q {\n%s}\n", path, body)
	}
	return stanza(mount+"/gateway*") + stanza(mount+"/role/+/gateway*")
}

// CertAgentPath is the default agent leg: the agent proves itself with a client
// certificate, leaving every header free.
const CertAgentPath = "auth/cert/"

// JWTAgentPath is the agent leg for the shapes where the agent arrives as a
// bearer token in some header.
const JWTAgentPath = "auth/jwt/"

// SetFullChainLegs repoints a mount's two auth legs without rebuilding the
// environment, so one mount can be driven through several agent shapes. An empty
// userAuthPath opts the mount out of the user leg entirely, which is how the
// not-a-protected-resource cases are exercised.
func SetFullChainLegs(t *testing.T, port int, upstreamURL string, p ProviderEnv, autoAuthPath, userAuthPath string) {
	t.Helper()

	// user_auth_role is always written, empty when opting out: config writes
	// merge into the stored config, so clearing the path while leaving a role
	// behind is rejected as "user_auth_role requires user_auth_path".
	role := ""
	if userAuthPath != "" {
		role = FullChainUserAuthRole
	}
	cfg := map[string]any{
		p.URLKey:          upstreamURL,
		"tls_skip_verify": true,
		"auto_auth_path":  autoAuthPath,
		"user_auth_path":  userAuthPath,
		"user_auth_role":  role,
	}
	for k, v := range p.ExtraConfig {
		cfg[k] = v
	}
	mustAPI(t, port, "POST", p.Mount+"/config", mustJSON(t, cfg), "repoint auth legs for "+p.Mount)
}

// ResetFullChainLegs restores the package default: certificate agent, user leg
// on. Tests that repoint must defer this so ordering cannot matter.
func ResetFullChainLegs(t *testing.T, port int, upstreamURL string, p ProviderEnv) {
	t.Helper()
	SetFullChainLegs(t, port, upstreamURL, p, CertAgentPath, FullChainUserAuthMount)
}

// ChainOpts describes how a full-chain request presents its credentials. Every
// field maps to one inbound channel, so a test row reads as the combination it
// is exercising.
type ChainOpts struct {
	// AgentCertPEM presents the agent as a client certificate, forwarded as a
	// header. It is honoured because the e2e listeners trust 127.0.0.1 as a
	// proxy; a client cannot forge it from anywhere else.
	AgentCertPEM string

	// WardenToken sets X-Warden-Token — the operator credential, which never
	// carries a user principal on either leg.
	WardenToken string

	// AgentToken sets X-Warden-Agent-Token, the dedicated agent channel that
	// leaves Authorization free for the user.
	AgentToken string

	// Bearer sets Authorization to a Bearer token.
	Bearer string

	// RawAuthz sets Authorization verbatim, for the providers whose agent rides
	// a native scheme such as "ApiKey " or "Splunk ".
	RawAuthz string

	// Role sets X-Warden-Role. It overrides every other role selector, and is
	// always stripped before the upstream.
	Role string

	// Headers are merged in last: native agent channels, and the decoys a test
	// expects the provider to strip.
	Headers map[string]string

	// Path is appended after the gateway prefix. Defaults to "probe".
	Path string

	// Method defaults to GET, or POST when Body is set.
	Method string

	// Body is the request body. Sending one matters beyond the payload itself:
	// policy that reads the body only engages on a request that has one, so a
	// rule about what a caller may ask for cannot be exercised without it.
	//
	// Content-Type defaults to application/json, which is also what decides
	// whether a provider opts the request into body-authoritative policy.
	Body string
}

// chainHeaders turns the credential-bearing options into request headers. Shared
// by the buffered and streaming paths so a row means the same thing either way.
func chainHeaders(t *testing.T, o ChainOpts) map[string]string {
	t.Helper()

	headers := map[string]string{}
	if o.AgentCertPEM != "" {
		headers["X-SSL-Client-Cert"] = URLEncodePEM(o.AgentCertPEM)
	}
	if o.WardenToken != "" {
		headers["X-Warden-Token"] = o.WardenToken
	}
	if o.AgentToken != "" {
		headers["X-Warden-Agent-Token"] = o.AgentToken
	}
	// Both write Authorization, so setting both would silently discard one and
	// the row would test something other than what it reads as.
	if o.Bearer != "" && o.RawAuthz != "" {
		t.Fatal("ChainOpts: set Bearer or RawAuthz, not both — they both write Authorization")
	}
	if o.Bearer != "" {
		headers["Authorization"] = "Bearer " + o.Bearer
	}
	if o.RawAuthz != "" {
		headers["Authorization"] = o.RawAuthz
	}
	if o.Role != "" {
		headers["X-Warden-Role"] = o.Role
	}
	for k, v := range o.Headers {
		headers[k] = v
	}
	return headers
}

func chainMethod(o ChainOpts) string {
	if o.Method != "" {
		return o.Method
	}
	if o.Body != "" {
		return "POST"
	}
	return "GET"
}

func chainURL(port int, p ProviderEnv, o ChainOpts) string {
	path := o.Path
	if path == "" {
		path = "probe"
	}
	return fmt.Sprintf("%s/v1/%s/gateway/%s", NodeURL(port), p.Mount, path)
}

func chainBody(o ChainOpts) io.Reader {
	if o.Body == "" {
		return nil
	}
	return strings.NewReader(o.Body)
}

// ChainRequest drives one request through the whole chain and returns the
// response status, body and headers. Response headers matter here because the
// user leg is largely a header protocol: WWW-Authenticate carries the challenge
// that says which principal was rejected.
func ChainRequest(t *testing.T, port int, p ProviderEnv, o ChainOpts) (int, []byte, http.Header) {
	t.Helper()

	req, err := http.NewRequest(chainMethod(o), chainURL(port, p, o), chainBody(o))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	applyHeaders(req, chainHeaders(t, o))
	if o.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Deliberately not DoRequestWithResponseHeaders: that client is shared with
	// other suites and follows redirects, which would hide a follower falling
	// back to one. See chainClient.
	resp, err := chainClient().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, body, resp.Header
}

// ChainStream drives a full-chain request and returns the live response without
// reading its body, so a test can observe chunks as they arrive.
//
// Every other row reads the body to completion, which cannot tell a streamed
// response from a buffered one: both end with the same bytes in hand. The
// difference is only visible in when they arrive, so it needs the response open.
//
// The caller owns resp.Body and must close it.
func ChainStream(t *testing.T, port int, p ProviderEnv, o ChainOpts) *http.Response {
	t.Helper()

	req, err := http.NewRequest(chainMethod(o), chainURL(port, p, o), chainBody(o))
	if err != nil {
		t.Fatalf("build streaming request: %v", err)
	}
	applyHeaders(req, chainHeaders(t, o))
	if o.Body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := chainClient().Do(req)
	if err != nil {
		t.Fatalf("streaming request failed: %v", err)
	}
	return resp
}

// chainClient is the HTTP client both chain paths use.
//
// Redirects are surfaced rather than followed. A follower that cannot reach the
// leader answers 307 pointing at the leader's own address, and Go would follow
// it — re-sending Authorization, and X-SSL-Client-Cert too, since that is not a
// header Go treats as sensitive. Every row aimed at a follower would then
// quietly exercise the direct path and still pass, unable to fail for the
// absence of the hop it exists to cover. Surfaced, the 307 fails the status
// assertion instead.
func chainClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed e2e cert
			// Compression would coalesce an upstream's chunks, hiding the
			// boundaries the streaming rows exist to observe.
			DisableCompression: true,
		},
	}
}

// ChainWant is what a full-chain request is expected to have produced.
type ChainWant struct {
	// Status is the response status the caller must have received.
	Status int

	// Injected are headers the upstream must have received, with exactly these
	// values. This is where a credential extractor's positive branch is pinned.
	Injected map[string]string

	// Absent are headers the upstream must not have received at all — the
	// caller's own credential, Warden's internal headers, and any decoy the
	// provider claims to strip.
	Absent []string

	// UpstreamCalls is how many requests the upstream should have seen. Set it
	// to 0 for a denial: a policy that rejects after the request has already
	// been forwarded is not a policy.
	UpstreamCalls int
}

// AssertChain checks a full-chain outcome: the caller's status, and what the
// upstream was and was not sent.
func AssertChain(t *testing.T, up *RecordingUpstream, status int, body []byte, want ChainWant) {
	t.Helper()

	if status != want.Status {
		t.Fatalf("status: got %d, want %d (body: %s)", status, want.Status, truncate(body))
	}

	reqs := up.Requests()
	if len(reqs) != want.UpstreamCalls {
		t.Fatalf("upstream received %d requests, want %d", len(reqs), want.UpstreamCalls)
	}
	if want.UpstreamCalls == 0 {
		return
	}

	// Only the last request's headers are inspected, which is why every row so
	// far expects exactly one. A row expecting several would need to say which.
	got := reqs[len(reqs)-1].Header
	failed := false
	fail := func(format string, args ...any) {
		failed = true
		t.Errorf(format, args...)
	}

	for name, wantValue := range want.Injected {
		if wantValue == "" {
			// Get returns "" for a header that never arrived, so an empty
			// expectation would be satisfied by absence. Absence belongs in
			// Absent, where it is stated as such.
			fail("Injected[%s] is empty; use Absent to assert a header is not forwarded", name)
			continue
		}
		// Values, not Get: a leak that appends to a header the provider also
		// injects leaves the injected value first, so Get would report success
		// while the caller's credential rode along behind it.
		switch gotValues := got.Values(name); {
		case len(gotValues) == 0:
			fail("upstream header %s: not forwarded, want %q", name, wantValue)
		case len(gotValues) > 1:
			fail("upstream header %s: got %d values %q, want exactly one (%q)", name, len(gotValues), gotValues, wantValue)
		case gotValues[0] != wantValue:
			fail("upstream header %s: got %q, want %q", name, gotValues[0], wantValue)
		}
	}
	for _, name := range want.Absent {
		if gotValues := got.Values(name); len(gotValues) > 0 {
			fail("upstream header %s should not have been forwarded, got %q", name, gotValues)
		}
	}
	// Guarded on this call's own failures: t.Failed() would also be true for an
	// unrelated earlier failure, attaching a header dump that explains nothing.
	if failed {
		t.Logf("upstream received headers: %s", formatHeaders(got))
	}
}

// AlwaysAbsent lists the headers no provider may ever forward: every internal
// channel that carries a token or selects an identity, plus the forwarded client
// certificate.
//
// An absence assertion only bites when the header was actually sent inbound —
// otherwise it holds however broken the strip list is. Pair this with
// InertDecoyHeaders on at least one row per provider so the claim is tested
// rather than merely stated.
//
// Authorization is deliberately not in the list. Several providers inject their
// credential into it, so asserting it absent is only meaningful where they do
// not — pass it explicitly there.
func AlwaysAbsent(extra ...string) []string {
	base := []string{
		"X-Warden-Token",
		"X-Warden-Agent-Token",
		"X-Warden-User-Token",
		"X-Warden-Role",
		"X-Warden-Provider",
		"X-Warden-Subject-Token",
		"X-Warden-Actor-Token",
		"X-SSL-Client-Cert",
	}
	return append(base, extra...)
}

// InertDecoyHeaders are internal channels a caller can set that carry no inbound
// meaning on a gateway request. Sending them is what turns the corresponding
// AlwaysAbsent entries from free into load-bearing: without them the strip list
// could drop these names entirely and every row would still pass.
//
// The internal headers NOT here all have inbound meaning, so sending them as
// decoys would change what is under test rather than exercise the strip:
//   - X-Warden-Agent-Token authenticates the agent, and is exercised as a real
//     credential instead.
//   - X-Warden-Token is the operator credential. With Authorization it trips the
//     ambiguity gate; alone it binds no credential spec — so no request carrying
//     it ever reaches an upstream to be inspected.
//   - X-Warden-Role selects the role, and every row already sends it.
//   - X-Warden-Provider selects the mount: it puts the request into
//     header-routing mode, so a decoy value reroutes it to a mount that does not
//     exist.
//
// Those four are therefore covered by the rows that use them for real, not here.
func InertDecoyHeaders() map[string]string {
	return map[string]string{
		"X-Warden-User-Token":    "decoy-user-token",
		"X-Warden-Subject-Token": "decoy-subject-token",
		"X-Warden-Actor-Token":   "decoy-actor-token",
	}
}

var (
	// runNonce separates this process's requests from every earlier run's.
	runNonce = strconv.FormatInt(time.Now().UnixNano(), 36)
	// probeSeq separates repeated calls within one process, which the nonce
	// alone cannot: -count=2 re-runs every test in the same process.
	probeSeq atomic.Uint64
)

// ProbePath returns a gateway sub-path unique to this call, for a test that will
// later look its request up in the audit log.
//
// The audit log is append-only and outlives a single `go test` invocation, so a
// fixed path matches every previous run's entries too. An assertion could then
// be satisfied by an entry written minutes ago — passing without the current
// request having been audited at all, and silently ignoring a regression that
// only affects the request just made.
//
// Call it ONCE per request and keep the result in a variable; calling it again
// for the same request yields a different path that matches nothing. Uniqueness
// is per call rather than per name so that -count=2 cannot let the second run's
// assertion be satisfied by the first run's entries.
func ProbePath(name string) string {
	return fmt.Sprintf("%s-%s-%d", name, runNonce, probeSeq.Add(1))
}

// AssertAuditUser checks how a request was attributed. wantUser is a substring
// of the user principal's subject, or "" to assert that no user was captured —
// the agent-only case, which must not silently acquire one.
//
// pathSubstr must come from ProbePath, or the lookup may match an earlier run.
//
// Polls, because audit writes are not synchronous with the response. Both cases
// wait for the response-phase entry rather than the first entry that appears.
// For the positive case that is merely the earliest point the user is certain to
// have been stamped; for the negative case it is what makes the assertion mean
// anything at all. Concluding "no user" from the request-phase entry would rest
// on the user being captured before that entry is written — true today, but a
// silent invariant, and if it ever changed every no-user assertion here would
// pass unconditionally rather than fail.
func AssertAuditUser(t *testing.T, port int, pathSubstr, wantUser string) {
	t.Helper()

	nodeNum := NodeNumberForPort(port)
	deadline := time.Now().Add(10 * time.Second)

	// Tracked across iterations so a timeout can say which of the three things
	// went wrong: nothing was written, the response half never arrived, or it
	// arrived carrying the wrong principal. Reporting the first when it was the
	// third sends the reader looking at the audit device instead of at the
	// principal that never got captured.
	var everSawAuth, everSawResponse bool

	for time.Now().Before(deadline) {
		var sawResponse bool
		var gotUser string
		for _, e := range ReadAuditEntries(t, nodeNum, pathSubstr) {
			if e.Auth == nil {
				continue
			}
			everSawAuth = true
			if e.Type == auditResponseEntry {
				sawResponse = true
			}
			if e.Auth.User != nil && e.Auth.User.Subject != "" {
				gotUser = e.Auth.User.Subject
			}
		}
		everSawResponse = everSawResponse || sawResponse

		if sawResponse {
			switch {
			case wantUser == "" && gotUser != "":
				t.Errorf("request %q was attributed to user %q, want no user principal", pathSubstr, gotUser)
			case wantUser == "":
				// Fully audited, no user captured — as intended.
			case strings.Contains(gotUser, wantUser):
				// Attributed to the expected user.
			case gotUser == "":
				t.Errorf("request %q was audited but attributed to no user; want one containing %q", pathSubstr, wantUser)
			default:
				t.Errorf("request %q: audit user %q does not contain %q", pathSubstr, gotUser, wantUser)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	switch {
	case everSawResponse:
		t.Errorf("request %q was audited but never attributed to a user containing %q", pathSubstr, wantUser)
	case everSawAuth:
		t.Errorf("request %q was audited but its response entry never arrived within the deadline", pathSubstr)
	default:
		t.Errorf("no audit entry with authentication context matched %q within the deadline", pathSubstr)
	}
}

// FullChainUserSubject is the subject carried by FullChainUserJWT. Asserted as a
// substring, since the auth method may qualify it.
const FullChainUserSubject = "e2e-pipeline"

// FullChainUserJWT returns a JWT for the USER principal — a different client,
// and therefore a different subject, than the agent's.
func FullChainUserJWT(t *testing.T) string {
	t.Helper()
	return GetJWT(t, "e2e-pipeline", "pipeline-secret")
}

// TeardownFullChainProviderBestEffort removes everything SetupFullChainProvider
// created. Best-effort throughout: cleanup must not fail a run that passed.
func TeardownFullChainProviderBestEffort(port int, p ProviderEnv) {
	del := bestEffortDeleter(port)
	for name := range p.Variants {
		del("auth/cert/role/" + p.VariantRole(name))
		del("sys/cred/specs/" + p.VariantSpec(name))
	}
	del("auth/jwt/role/" + p.JWTAgentRole())
	del("auth/cert/role/" + p.DenyRole())
	del("sys/policies/cbp/" + p.DenyPolicy())
	del("auth/cert/role/" + p.CertRole())
	del("sys/policies/cbp/" + p.Policy())
	del("sys/cred/specs/" + p.Spec())
	del("sys/cred/sources/" + p.Source())
	del("sys/providers/" + p.Mount)
}

// TeardownFullChainCommonBestEffort removes the shared auth mounts.
func TeardownFullChainCommonBestEffort(port int) {
	del := bestEffortDeleter(port)
	del("auth/fullchain-user-jwt/role/" + FullChainUserAuthRole)
	del("sys/auth/fullchain-user-jwt")
	del("sys/auth/cert")
	time.Sleep(time.Second)
}

// RootTokenBestEffort reads the root token without a *testing.T, for teardown
// from TestMain where a zero-value T cannot be used.
func RootTokenBestEffort() string {
	return rootTokenBestEffort()
}

func bestEffortDeleter(port int) func(string) {
	token := rootTokenBestEffort()
	return func(path string) {
		TryRequest("DELETE", fmt.Sprintf("%s/v1/%s", NodeURL(port), path),
			map[string]string{"X-Warden-Token": token}, "")
	}
}

// mustJSON marshals a config body, failing the test rather than returning an
// error: a test that cannot express its own fixture has nothing left to check.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	return string(b)
}

// formatHeaders renders received headers in a stable order, so a failure
// message can be read against the expectation that produced it.
func formatHeaders(h http.Header) string {
	names := make([]string, 0, len(h))
	for name := range h {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		fmt.Fprintf(&b, "\n  %s: %s", name, strings.Join(h[name], ", "))
	}
	return b.String()
}

func truncate(body []byte) string {
	const max = 512
	if len(body) <= max {
		return string(body)
	}
	return string(body[:max]) + "..."
}
