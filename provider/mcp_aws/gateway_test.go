package mcp_aws

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/provider/sdk/sigv4"
)

// captured holds what the upstream test server saw.
type captured struct {
	mu      sync.Mutex
	method  string
	host    string
	path    string
	headers http.Header
	body    []byte
}

func (c *captured) snapshot() captured {
	c.mu.Lock()
	defer c.mu.Unlock()
	return captured{
		method:  c.method,
		host:    c.host,
		path:    c.path,
		headers: c.headers.Clone(),
		body:    append([]byte(nil), c.body...),
	}
}

// newCapturingUpstream stands up a test server that records the first request
// it receives and returns 200 with a fixed body.
func newCapturingUpstream(t *testing.T) (*httptest.Server, *captured) {
	t.Helper()
	cap := &captured{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cap.mu.Lock()
		cap.method = r.Method
		cap.host = r.Host
		cap.path = r.URL.Path
		cap.headers = r.Header.Clone()
		cap.body = body
		cap.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	return srv, cap
}

// configureBackendForUpstream points the backend at the test server's URL,
// preserving the test-server-supplied TLS transport so the request actually
// reaches it.
func configureBackendForUpstream(t *testing.T, b *mcpAWSBackend, srv *httptest.Server) {
	t.Helper()
	u, err := url.Parse(srv.URL + "/mcp")
	require.NoError(t, err)
	b.mu.Lock()
	b.upstreamURL = u
	b.region = "us-east-1"
	b.mu.Unlock()
	b.SetTransport(srv.Client().Transport)
}

// makeMCPRequest builds a *logical.Request as if a Warden bearer-token client
// had POSTed the given JSON-RPC body to the gateway path. The Path arg is the
// inbound URL path (e.g. "/gateway/" or "/role/s3-reader/gateway/tools/call").
func makeMCPRequest(path, body string, cred *credential.Credential) (*logical.Request, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodPost, "https://warden.example.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	// Headers that mcp_aws must strip before signing.
	r.Header.Set("Authorization", "Bearer warden-session-token")
	r.Header.Set("X-Warden-Token", "warden-session-token")
	r.Header.Set("X-Warden-Namespace", "team-data")
	r.Header.Set("X-Warden-Provider", "mcp_aws/")
	r.Header.Set("X-Warden-Role", "s3-reader")
	r.Header.Set("X-Warden-On-Behalf-Of", "alice@example.com")
	// Hop-by-hop that NormalizeRequest must drop.
	r.Header.Set("Connection", "keep-alive")

	rec := httptest.NewRecorder()
	return &logical.Request{
		HTTPRequest:    r,
		ResponseWriter: rec,
		Path:           strings.TrimPrefix(path, "/"),
		Credential:     cred,
	}, rec
}

func stsCredential() *credential.Credential {
	return &credential.Credential{
		Type: credential.TypeAWSAccessKeys,
		Data: map[string]string{
			"access_key_id":     "ASIAEXAMPLE0000ABCD",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"session_token":     "session-token-from-sts",
		},
	}
}

func longLivedCredential() *credential.Credential {
	return &credential.Credential{
		Type: credential.TypeAWSAccessKeys,
		Data: map[string]string{
			"access_key_id":     "AKIAEXAMPLE0000ABCD",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			// no session_token
		},
	}
}

// --- happy path / STS creds ---

func TestHandleGateway_SignsAndForwards_STS(t *testing.T) {
	srv, capRec := newCapturingUpstream(t)
	defer srv.Close()

	b := setupBackend(t)
	configureBackendForUpstream(t, b, srv)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req, rec := makeMCPRequest("/gateway/", body, stsCredential())

	b.handleGateway(context.Background(), req)

	require.Equal(t, http.StatusOK, rec.Code, "upstream should have returned 200")

	got := capRec.snapshot()
	assert.Equal(t, http.MethodPost, got.method)
	assert.Equal(t, "/mcp/", got.path, "trailing slash on gateway/ must reach upstream as /mcp/")
	assert.Equal(t, body, string(got.body), "body must reach upstream unmodified")

	// Signature parses as SigV4.
	auth := got.headers.Get("Authorization")
	require.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256 "), "Authorization must be SigV4: %q", auth)
	service, region, accessKey, err := sigv4.ExtractFromAuthHeader(auth)
	require.NoError(t, err)
	assert.NotEmpty(t, service, "credential scope service must be derived from upstream URL host")
	assert.Equal(t, "us-east-1", region)
	assert.True(t, strings.HasPrefix(accessKey, "ASIA"), "STS-minted creds yield ASIA-prefixed access keys, got %q", accessKey)

	// STS session token must flow through as X-Amz-Security-Token.
	assert.Equal(t, "session-token-from-sts", got.headers.Get("X-Amz-Security-Token"))

	// SigV4 ancillary headers present.
	assert.NotEmpty(t, got.headers.Get("X-Amz-Date"))
	assert.NotEmpty(t, got.headers.Get("X-Amz-Content-Sha256"))

	// No Warden header leak.
	for _, h := range []string{"X-Warden-Token", "X-Warden-Namespace", "X-Warden-Provider", "X-Warden-Role", "X-Warden-On-Behalf-Of"} {
		assert.Empty(t, got.headers.Get(h), "header %q leaked to upstream", h)
	}
	// No Bearer leak — Authorization must be SigV4 only.
	assert.NotContains(t, auth, "Bearer", "Authorization leaked Bearer token")

	// Connection must not appear in the SignedHeaders list.
	assert.NotContains(t, strings.ToLower(auth), ";connection", "Connection must not be a signed header")
}

// --- long-lived keys: no session token ---

func TestHandleGateway_SignsAndForwards_LongLivedKeys(t *testing.T) {
	srv, capRec := newCapturingUpstream(t)
	defer srv.Close()

	b := setupBackend(t)
	configureBackendForUpstream(t, b, srv)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req, rec := makeMCPRequest("/gateway/", body, longLivedCredential())

	b.handleGateway(context.Background(), req)
	require.Equal(t, http.StatusOK, rec.Code)

	got := capRec.snapshot()
	auth := got.headers.Get("Authorization")
	_, _, accessKey, err := sigv4.ExtractFromAuthHeader(auth)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(accessKey, "AKIA"), "long-lived creds yield AKIA-prefixed access keys, got %q", accessKey)
	// X-Amz-Security-Token must be absent when no session token is present.
	assert.Empty(t, got.headers.Get("X-Amz-Security-Token"), "long-lived creds must not carry a security token")
}

// --- trailing-slash + tail preservation ---

func TestHandleGateway_TrailingSlashPreservedOnRoot(t *testing.T) {
	srv, capRec := newCapturingUpstream(t)
	defer srv.Close()
	b := setupBackend(t)
	configureBackendForUpstream(t, b, srv)

	req, rec := makeMCPRequest("/gateway/", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, stsCredential())
	b.handleGateway(context.Background(), req)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.Equal(t, "/mcp/", capRec.snapshot().path, "gateway/ must preserve trailing slash")
}

func TestHandleGateway_DeepTailPreserved(t *testing.T) {
	srv, capRec := newCapturingUpstream(t)
	defer srv.Close()
	b := setupBackend(t)
	configureBackendForUpstream(t, b, srv)

	req, rec := makeMCPRequest("/gateway/tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, stsCredential())
	b.handleGateway(context.Background(), req)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.Equal(t, "/mcp/tools/call", capRec.snapshot().path)
}

func TestHandleGateway_RolePrefixedPath(t *testing.T) {
	srv, capRec := newCapturingUpstream(t)
	defer srv.Close()
	b := setupBackend(t)
	configureBackendForUpstream(t, b, srv)

	req, rec := makeMCPRequest("/role/s3-reader/gateway/tools/call", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, stsCredential())
	b.handleGateway(context.Background(), req)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.Equal(t, "/mcp/tools/call", capRec.snapshot().path)
}

// --- error paths ---

func TestHandleGateway_WrongCredentialType(t *testing.T) {
	srv, _ := newCapturingUpstream(t)
	defer srv.Close()
	b := setupBackend(t)
	configureBackendForUpstream(t, b, srv)

	wrongCred := &credential.Credential{
		Type: credential.TypeGitHubToken,
		Data: map[string]string{"token": "ghp_xxx"},
	}
	req, rec := makeMCPRequest("/gateway/", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, wrongCred)
	b.handleGateway(context.Background(), req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code, "wrong credential type is a programmer error, must surface as 500")
}

// --- AgentCore service name routing ---

// redirectTransport rewrites every outbound request to target a local test
// server while leaving r.URL.Host and r.Host untouched on the signed request.
// This lets us assert that mcp_aws derives the correct SigV4 service name
// (e.g. "bedrock-agentcore") from a fake upstream host without standing up
// AWS DNS.
type redirectTransport struct {
	target *url.URL
	inner  http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL = &url.URL{
		Scheme:   rt.target.Scheme,
		Host:     rt.target.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	// Leave clone.Host as the original — this is what the signed Host header
	// expects to see; the transport just dials a different address.
	return rt.inner.RoundTrip(clone)
}

// TestHandleGateway_ThroughConfigWrite drives the gateway via the same path
// production uses: handleConfigWrite sets up state, then handleGateway runs.
// Catches regressions that the configureBackendForUpstream backdoor (which
// mutates b.upstreamURL directly) would miss — for example, a misnamed
// persisted field or a missed lock in applyParsedConfig.
func TestHandleGateway_ThroughConfigWrite(t *testing.T) {
	srv, capRec := newCapturingUpstream(t)
	defer srv.Close()

	b := setupBackend(t)
	// Point the shared transport at the test server's TLS config so the
	// upstream URL (which we'll set to the test server URL via config-write)
	// resolves correctly.
	b.SetTransport(srv.Client().Transport)

	path := b.pathConfig()
	fd := makeFieldData(path, map[string]any{
		"mcp_aws_url":    srv.URL + "/mcp",
		"region":         "us-east-1",
		"auto_auth_path": "auth/jwt/",
	})
	resp, err := b.handleConfigWrite(context.Background(), nil, fd)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Config-write rebuilt the transport via applyParsedConfig. We need to
	// re-point it at the test server (no TLS overrides → shared transport).
	b.SetTransport(srv.Client().Transport)

	req, rec := makeMCPRequest("/gateway/", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, stsCredential())
	b.handleGateway(context.Background(), req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capRec.snapshot().headers.Get("Authorization"))
}

func TestHandleGateway_AgentCoreServiceInference(t *testing.T) {
	srv, capRec := newCapturingUpstream(t)
	defer srv.Close()

	b := setupBackend(t)
	agentCoreURL, _ := url.Parse("https://runtime.bedrock-agentcore.us-east-1.amazonaws.com/agents/myMcp/invocations")
	srvURL, _ := url.Parse(srv.URL)
	b.mu.Lock()
	b.upstreamURL = agentCoreURL
	b.region = "us-east-1"
	b.mu.Unlock()
	b.SetTransport(&redirectTransport{
		target: srvURL,
		inner:  srv.Client().Transport,
	})

	req, rec := makeMCPRequest("/gateway/", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, stsCredential())
	b.handleGateway(context.Background(), req)
	require.Equal(t, http.StatusOK, rec.Code)

	auth := capRec.snapshot().headers.Get("Authorization")
	service, region, _, err := sigv4.ExtractFromAuthHeader(auth)
	require.NoError(t, err)
	assert.Equal(t, "bedrock-agentcore", service, "AgentCore host must yield service=bedrock-agentcore via arm 1 of the structured match")
	assert.Equal(t, "us-east-1", region)
}

// --- MCP list-response filtering ---

// TestHandleGateway_FiltersToolsList drives the full mcp_aws gateway with a
// list filter attached, proving the response is pruned to the callable items.
func TestHandleGateway_FiltersToolsList(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_x"},{"name":"delete_x"}]}}`))
	}))
	defer srv.Close()

	b := setupBackend(t)
	configureBackendForUpstream(t, b, srv)

	req, rec := makeMCPRequest("/gateway/", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, stsCredential())
	req.MCPListFilter = &logical.MCPListFilter{
		ListMethod: "tools/list",
		Keep:       func(name string) bool { return !strings.HasPrefix(name, "delete_") },
	}

	b.handleGateway(context.Background(), req)

	require.Equal(t, http.StatusOK, rec.Code)
	out := rec.Body.String()
	assert.Contains(t, out, "get_x")
	assert.NotContains(t, out, "delete_x", "denied tool must be pruned from the mcp_aws tools/list response")
}
