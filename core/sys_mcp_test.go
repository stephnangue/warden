package core

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/listener"
)

// mcpHeaderRoundTripper injects a fixed set of headers on every outbound
// request, letting the SDK client present a JWT identity (Authorization) and
// select a namespace (X-Warden-Namespace) against the discovery endpoint.
type mcpHeaderRoundTripper struct {
	base    http.RoundTripper
	headers map[string]string
}

func (rt mcpHeaderRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	for k, v := range rt.headers {
		if v != "" {
			r.Header.Set(k, v)
		}
	}
	return rt.base.RoundTrip(r)
}

// startMCPTestServer serves the MCP discovery handler over HTTP. When cert is
// non-nil, each request is wrapped with a forwarded client certificate in its
// context, simulating the listener's certForwardingMiddleware so the X.509
// credential path can be exercised end-to-end (the SDK does not surface the
// client cert to tool handlers, so the handler must recover it from the
// threaded request context).
func startMCPTestServer(t *testing.T, c *Core, cert *x509.Certificate) *httptest.Server {
	t.Helper()
	handler := c.MCPServerHandler()
	if cert != nil {
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := listener.WithForwardedClientCert(r.Context(), cert)
			inner.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// connectMCP dials the discovery endpoint with an optional bearer token and
// returns a connected client session.
func connectMCP(t *testing.T, srv *httptest.Server, bearer string) *mcp.ClientSession {
	return connectMCPWithHeaders(t, srv, map[string]string{"Authorization": bearerHeader(bearer)})
}

// bearerHeader formats a bearer token as an Authorization header value, or ""
// when no token is presented.
func bearerHeader(bearer string) string {
	if bearer == "" {
		return ""
	}
	return "Bearer " + bearer
}

// connectMCPWithHeaders dials the discovery endpoint injecting the given
// headers on every request and returns a connected client session.
func connectMCPWithHeaders(t *testing.T, srv *httptest.Server, headers map[string]string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1.0.0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             srv.URL + "/v1/sys/mcp",
		HTTPClient:           &http.Client{Transport: mcpHeaderRoundTripper{base: http.DefaultTransport, headers: headers}},
		DisableStandaloneSSE: true,
	}
	session, err := client.Connect(context.Background(), transport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// decodeListRoles asserts a successful list_roles result and returns the
// structured output.
func decodeListRoles(t *testing.T, res *mcp.CallToolResult) listRolesOutput {
	t.Helper()
	require.False(t, res.IsError, "unexpected tool error: %v", res.Content)
	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	var out listRolesOutput
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// TestMCPServer_ListRoles_JWTFanOut drives the full transport with a Bearer
// JWT: the handshake negotiates the latest protocol revision, tools/list
// advertises list_roles, and the tool result matches what the introspection
// aggregator returns for a JWT identity.
func TestMCPServer_ListRoles_JWTFanOut(t *testing.T) {
	_, ctx, c := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()

	c.authMethods["jwt"] = ctrl.factory()
	require.NoError(t, c.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt-a/"}))
	require.NoError(t, c.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt-b/"}))
	ctrl.rolesByMount["auth/jwt-a/"] = []map[string]any{
		{"name": "reader", "description": "search & read any repo (skill: github)"},
	}
	ctrl.rolesByMount["auth/jwt-b/"] = []map[string]any{
		{"name": "writer", "description": "write staging"},
	}

	srv := startMCPTestServer(t, c, nil)
	session := connectMCP(t, srv, "eyJ.any.token")

	// The SDK client requests the latest revision and uses the SEP-2575
	// server/discover RPC; the negotiated version is the end-of-July RC.
	require.NotNil(t, session.InitializeResult())
	assert.Equal(t, "2026-07-28", session.InitializeResult().ProtocolVersion)

	// tools/list advertises list_roles.
	tools, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	assert.Contains(t, names, "list_roles")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(t, err)
	out := decodeListRoles(t, res)

	// Sorted by auth_path then name: jwt-a/reader, jwt-b/writer. auth_path is
	// dropped from the projection — only {name, description} survive.
	require.Len(t, out.Roles, 2)
	assert.Equal(t, "reader", out.Roles[0].Name)
	assert.Equal(t, "search & read any repo (skill: github)", out.Roles[0].Description)
	assert.Equal(t, "writer", out.Roles[1].Name)
	assert.Empty(t, out.Warnings)
}

// TestMCPServer_ListRoles_CertPath exercises the X.509 credential path: no
// Authorization header is sent, only a forwarded client certificate. This
// proves the capturing middleware threads the cert (which the SDK does not
// surface to tool handlers) through to detectIntrospectCredentialFormat.
func TestMCPServer_ListRoles_CertPath(t *testing.T) {
	_, ctx, c := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()

	c.authMethods["cert"] = ctrl.factory()
	require.NoError(t, c.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "cert", Path: "cert-mount/"}))
	ctrl.rolesByMount["auth/cert-mount/"] = []map[string]any{
		{"name": "cert-role", "description": "clone via Git (skill: github)"},
	}

	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent"}}
	srv := startMCPTestServer(t, c, cert)
	session := connectMCP(t, srv, "") // identity is the cert, not a bearer token

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(t, err)
	out := decodeListRoles(t, res)

	require.Len(t, out.Roles, 1)
	assert.Equal(t, "cert-role", out.Roles[0].Name)
}

// TestMCPServer_ListRoles_NoCredential asserts that a call with neither a
// bearer token nor a client cert returns an MCP tool error (mirroring the
// endpoint's 401) rather than a protocol-level failure, so the model can see
// the error and self-correct.
func TestMCPServer_ListRoles_NoCredential(t *testing.T) {
	_, _, c := setupTestSystemBackend(t)
	srv := startMCPTestServer(t, c, nil)
	session := connectMCP(t, srv, "")

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(t, err)
	require.True(t, res.IsError, "no-credential call must be a tool error")
	require.NotEmpty(t, res.Content)
	txt, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	assert.Contains(t, txt.Text, "JWT bearer token or TLS client certificate")
}

// TestMCPServer_SealedNode_Returns503 pins that the discovery route rejects
// cleanly on a sealed node instead of nil-panicking. This route bypasses
// HandleRequest's seal guard, and seal nils c.namespaceStore, so the handler
// must short-circuit on c.Sealed() before touching it.
func TestMCPServer_SealedNode_Returns503(t *testing.T) {
	_, _, c := setupTestSystemBackend(t)

	// Simulate seal: flip the sealed flag and drop the namespace store, exactly
	// as teardownNamespaceStore does. The handler must not dereference it.
	atomic.StoreUint32(c.sealed, 1)
	c.namespaceStore = nil

	srv := startMCPTestServer(t, c, nil)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/sys/mcp", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestMCPServer_ProtocolNegotiation_FallsBackForOlderClients drives the legacy
// initialize handshake directly with older protocol revisions and asserts the
// server negotiates each requested (supported) version rather than forcing the
// latest. The SEP-2575 discover path for the latest revision is covered by
// TestMCPServer_ListRoles_JWTFanOut's InitializeResult assertion.
func TestMCPServer_ProtocolNegotiation_FallsBackForOlderClients(t *testing.T) {
	_, _, c := setupTestSystemBackend(t)
	srv := startMCPTestServer(t, c, nil)

	negotiate := func(t *testing.T, requested string) string {
		t.Helper()
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":%q,"capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`, requested)
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/sys/mcp", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var parsed struct {
			Result struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"result"`
		}
		require.NoError(t, json.Unmarshal(raw, &parsed), "body: %s", raw)
		return parsed.Result.ProtocolVersion
	}

	assert.Equal(t, "2025-11-25", negotiate(t, "2025-11-25"))
	assert.Equal(t, "2025-06-18", negotiate(t, "2025-06-18"))
}

// seedTestSkill installs a provider-guide skill named after the provider type.
func seedTestSkill(t *testing.T, c *Core, ctx context.Context, name string) {
	t.Helper()
	require.NoError(t, c.skillStore.Create(ctx, &Skill{
		Name:        name,
		Description: "drive " + name + " through the gateway",
		Category:    SkillCategoryProviderGuide,
		Provider:    name,
		Body:        "# Using " + name + "\nSend JSON-RPC to the gateway.",
	}))
}

// callGetSkill invokes the get_skill tool and returns the raw result.
func callGetSkill(t *testing.T, session *mcp.ClientSession, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_skill", Arguments: args})
	require.NoError(t, err)
	return res
}

// decodeSkill asserts a successful get_skill result and returns the skill map.
func decodeSkill(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	require.False(t, res.IsError, "unexpected tool error: %v", res.Content)
	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// TestMCPServer_GetSkill_ByName fetches a seeded skill by name and returns its
// markdown body and metadata.
func TestMCPServer_GetSkill_ByName(t *testing.T) {
	_, ctx, c := setupTestSystemBackend(t)
	seedTestSkill(t, c, ctx, "mcp")

	srv := startMCPTestServer(t, c, nil)
	session := connectMCP(t, srv, "eyJ.any.token")

	got := decodeSkill(t, callGetSkill(t, session, map[string]any{"skill": "mcp"}))
	assert.Equal(t, "mcp", got["name"])
	assert.Contains(t, got["body"].(string), "Using mcp")
}

// TestMCPServer_GetSkill_Errors covers the tool-error paths: a missing/blank
// skill name and an unknown skill name.
func TestMCPServer_GetSkill_Errors(t *testing.T) {
	_, ctx, c := setupTestSystemBackend(t)
	seedTestSkill(t, c, ctx, "mcp")

	srv := startMCPTestServer(t, c, nil)
	session := connectMCP(t, srv, "eyJ.any.token")

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"missing", map[string]any{}, "skill is required"},
		{"blank", map[string]any{"skill": "   "}, "skill is required"},
		{"unknown", map[string]any{"skill": "nope"}, `skill "nope" not found`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := callGetSkill(t, session, tc.args)
			require.True(t, res.IsError, "expected a tool error")
			require.NotEmpty(t, res.Content)
			txt, ok := res.Content[0].(*mcp.TextContent)
			require.True(t, ok)
			assert.Contains(t, txt.Text, tc.want)
		})
	}
}
