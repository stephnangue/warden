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
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
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

// requestPathHandler serves HTTP through the request path, as the http
// package's handleLogical does — the request built the same way, handed to
// HandleRequest, and the answer written back — which core cannot import. Only
// the shapes the discovery endpoint answers with are rendered: a streamed
// response (written by the backend), a body, an error, data.
func requestPathHandler(c *Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := logical.ReadOperation
		switch r.Method {
		case http.MethodPost:
			op = logical.CreateOperation
		case http.MethodPut:
			op = logical.UpdateOperation
		case http.MethodDelete:
			op = logical.DeleteOperation
		}
		req := &logical.Request{
			Operation:      op,
			Path:           strings.TrimPrefix(r.URL.Path, "/v1/"),
			HTTPRequest:    r,
			ResponseWriter: logical.NewStatusRecordingWriter(w),
		}
		resp, err := c.HandleRequest(r.Context(), req)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(logical.GetErrorCode(err))
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": logical.ErrorMessages(err)})
			return
		}
		switch {
		case resp == nil:
			w.WriteHeader(http.StatusNoContent)
		case resp.Streamed:
		default:
			for k, vs := range resp.Headers {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			status := resp.StatusCode
			if status == 0 {
				status = http.StatusOK
				if resp.Err != nil {
					status = logical.GetErrorCode(resp.Err)
				}
			}
			var body []byte
			switch {
			case len(resp.Body) > 0:
				body = resp.Body
			case resp.Err != nil:
				w.Header().Set("Content-Type", "application/json")
				body, _ = json.Marshal(map[string]any{"errors": logical.ErrorMessages(resp.Err)})
			case resp.Data != nil:
				w.Header().Set("Content-Type", "application/json")
				body, _ = json.Marshal(map[string]any{"data": resp.Data})
			}
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}
	})
}

// startMCPTestServer serves the request path over HTTP, the discovery
// endpoint at /v1/sys/mcp among it. When cert is non-nil, each request is
// wrapped with a forwarded client certificate in its context, simulating the
// listener's certForwardingMiddleware so the X.509 credential path can be
// exercised end-to-end (the SDK does not surface the client cert to tool
// handlers, so the handler must recover it from the threaded request context).
func startMCPTestServer(t *testing.T, c *Core, cert *x509.Certificate) *httptest.Server {
	t.Helper()
	handler := requestPathHandler(c)
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

// TestMCPServer_ListRoles_JWT drives the full transport with a Bearer JWT:
// the handshake negotiates the latest protocol revision, tools/list advertises
// list_roles, and the tool result lists the roles granted at each role's
// provider's auth mount.
func TestMCPServer_ListRoles_JWT(t *testing.T) {
	e := newDiscEnv(t, "", "")
	e.mountAuth("jwt-a/")
	e.mountAuth("jwt-b/")
	e.provider("vault", "vault/", "auth/jwt-a/")
	e.provider("github", "github/", "auth/jwt-b/")
	e.grant("readers", []string{"auth/jwt-a/"},
		&logical.Role{Name: "reader", Description: "search & read any repo", ProviderPath: "vault/"})
	e.grant("writers", []string{"auth/jwt-b/"},
		&logical.Role{Name: "writer", Description: "write staging", ProviderPath: "github/"})
	c := e.c

	srv := startMCPTestServer(t, c, nil)
	session := connectMCP(t, srv, "eyJ.any.token")

	// The SDK client requests the latest revision and uses the SEP-2575
	// server/discover RPC; the negotiated version is the end-of-July RC.
	require.NotNil(t, session.InitializeResult())
	assert.Equal(t, "2026-07-28", session.InitializeResult().ProtocolVersion)

	// tools/list advertises list_roles and read_skill; get_skill is gone.
	tools, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	assert.ElementsMatch(t, []string{"list_roles", "read_skill"}, names)

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.NoError(t, err)
	out := decodeListRoles(t, res)

	// Sorted by name.
	require.Len(t, out.Roles, 2)
	assert.Equal(t, "reader", out.Roles[0].Name)
	assert.Equal(t, "search & read any repo", out.Roles[0].Description)
	assert.Equal(t, "writer", out.Roles[1].Name)
	assert.Empty(t, out.Warnings)
}

// TestMCPServer_ListRoles_CertPath exercises the X.509 credential path: no
// Authorization header is sent, only a forwarded client certificate. This
// proves the capturing middleware threads the cert (which the SDK does not
// surface to tool handlers) through to the auth mount that admits it.
func TestMCPServer_ListRoles_CertPath(t *testing.T) {
	e := newDiscEnv(t, "", "")
	e.stub.nextFormat = logical.CredentialFormatCert
	e.mountAuth("cert-mount/").needCert = true
	e.provider("git", "git/", "auth/cert-mount/")
	e.grant("cloners", []string{"auth/cert-mount/"},
		&logical.Role{Name: "cert-role", Description: "clone via Git", ProviderPath: "git/"})
	c := e.c

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
// bearer token nor a client cert is refused by the request path with a 401,
// before the tool runs, while the anonymous handshake and tools/list still
// succeed, so a client connects and learns what it may call.
func TestMCPServer_ListRoles_NoCredential(t *testing.T) {
	_, _, c := setupTestSystemBackend(t)
	srv := startMCPTestServer(t, c, nil)
	session := connectMCP(t, srv, "")

	tools, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err, "tools/list needs no credential")
	assert.Len(t, tools.Tools, 2)

	_, err = session.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_roles"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Unauthorized")
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

// skillRoleEnv seeds the skill "mcp" and grants every credential the role
// "agent" naming it, a role without a provider reached at the namespace's
// auto_auth_path.
func skillRoleEnv(t *testing.T) *discEnv {
	t.Helper()
	e := setupDiscovery(t)
	seedTestSkill(t, e.c, rootCtx(), "mcp")
	e.grant("agents", []string{"auth/jwt/"}, &logical.Role{Name: "agent", Skill: "mcp"})
	return e
}

// callReadSkill invokes the read_skill tool and returns the raw result.
func callReadSkill(t *testing.T, session *mcp.ClientSession, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "read_skill", Arguments: args})
	require.NoError(t, err)
	return res
}

// TestMCPServer_ReadSkill_ByURI reads a seeded skill by its skill:// URI: the
// text content is the rendered SKILL.md, and the structured output carries its
// frontmatter and the same SKILL.md, so a client reading either gets the body.
func TestMCPServer_ReadSkill_ByURI(t *testing.T) {
	e := skillRoleEnv(t)
	stored, err := e.c.skillStore.Get(rootCtx(), "mcp")
	require.NoError(t, err)

	session := connectMCPWithHeaders(t, e.server(), e.headers("eyJ.any.token"))

	res := callReadSkill(t, session, map[string]any{"uri": "skill://mcp/SKILL.md"})
	require.False(t, res.IsError, "unexpected tool error: %v", res.Content)
	require.Len(t, res.Content, 1)
	txt, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok)
	md, err := renderSkillMarkdown(stored)
	require.NoError(t, err)
	assert.Equal(t, string(md), txt.Text)
	assert.Contains(t, txt.Text, "Using mcp")

	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)
	var out readSkillOutput
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.Equal(t, "skill://mcp/SKILL.md", out.URI)
	assert.Equal(t, frontmatterFor(stored), out.Frontmatter)
	assert.Equal(t, string(md), out.Markdown, "the body reaches a client that reads only the structured output")
}

// TestMCPServer_ReadSkill_Errors covers the tool-error paths: a missing,
// malformed or bare-name URI, and an unknown skill.
func TestMCPServer_ReadSkill_Errors(t *testing.T) {
	e := skillRoleEnv(t)
	session := connectMCPWithHeaders(t, e.server(), e.headers("eyJ.any.token"))

	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"blank", map[string]any{"uri": "   "}, "invalid skill URI"},
		{"bare name", map[string]any{"uri": "mcp"}, "invalid skill URI"},
		{"not SKILL.md", map[string]any{"uri": "skill://mcp/README.md"}, "invalid skill URI"},
		{"unknown", map[string]any{"uri": "skill://nope/SKILL.md"}, `skill "skill://nope/SKILL.md" not found`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := callReadSkill(t, session, tc.args)
			require.True(t, res.IsError, "expected a tool error")
			require.NotEmpty(t, res.Content)
			txt, ok := res.Content[0].(*mcp.TextContent)
			require.True(t, ok)
			assert.Contains(t, txt.Text, tc.want)
		})
	}
}

// TestMCPServerHandler_ShedsConnectionDeadlines pins the ordering the
// discovery endpoint depends on. The SDK forces SSE for subscriptions/listen
// and then blocks in hangResponse without writing a byte, so the deadlines
// cannot be shed reactively on seeing an event-stream Content-Type — by the
// time anything is written they have already fired, and an armed read
// deadline cancels the very context the SDK is blocked on. The body is read
// first, under the deadlines the listener armed, so a dribbling client stays
// bounded; only then are they shed.
func TestMCPServerHandler_ShedsConnectionDeadlines(t *testing.T) {
	c := createTestCore(t)
	w := newDeadlineRecordingWriter()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	r := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")

	requestPathHandler(c).ServeHTTP(w, r)

	require.NotEmpty(t, w.read, "an armed read deadline tears down an idle listen stream")
	require.NotEmpty(t, w.write, "an armed write deadline severs the stream on its first notification")
	assert.True(t, w.read[len(w.read)-1].IsZero(), "the body read window is closed once the body is in hand")
	assert.True(t, w.write[len(w.write)-1].IsZero())
}

// Buffering the body must leave it readable by the SDK, or every discovery
// call would fail as an empty request.
func TestMCPServerHandler_BufferedBodyStillReaches(t *testing.T) {
	c := createTestCore(t)
	rec := httptest.NewRecorder()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	r := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")

	requestPathHandler(c).ServeHTTP(rec, r)

	assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "list_roles", "the buffered body must reach the SDK unchanged")
}

// An oversized body is refused by the MCP gate before the server runs, as the
// transport refuses input it cannot accept: a 413.
func TestMCPServerHandler_RejectsOversizedBody(t *testing.T) {
	c := createTestCore(t)
	rec := httptest.NewRecorder()

	r := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", strings.NewReader(strings.Repeat("a", maxSysMCPBody+1)))
	r.Header.Set("Content-Type", "application/json")

	requestPathHandler(c).ServeHTTP(rec, r)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "body: %s", rec.Body.String())
}

// Shedding the listener's deadlines leaves this endpoint with no ceiling of
// its own, so it imposes one, the way a gateway mount imposes listen_timeout:
// nothing else ends a stalled request. The request path bounds its handler
// by it; the dev playground's self-check runs under the same ceiling.
func TestDiscoveryRequestContext_ImposesItsOwnCeiling(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", strings.NewReader("{}"))

	ctx, cancel := discoveryRequestContext(r, namespace.RootNamespace)
	defer cancel()

	deadline, ok := ctx.Deadline()
	require.True(t, ok, "the SDK blocks on this context; with no deadline nothing ends a stalled request")
	assert.InDelta(t, sysMCPTimeout, time.Until(deadline), float64(5*time.Second))

	// The namespace and raw request must survive the wrapping — the tool
	// handlers resolve mounts through the first and recover the caller's
	// credentials from the second.
	ns, err := namespace.FromContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, namespace.RootNamespaceID, ns.ID)
	assert.Same(t, r, discoveryRequestFromContext(ctx))
}

// postSysMCPBatch posts a JSON-RPC batch of n tools/list calls to the
// discovery endpoint through the request path, as a client on a revision that
// still batches would. tools/list needs no credential, so the batch is served
// anonymously.
func postSysMCPBatch(t *testing.T, c *Core, n int) *httptest.ResponseRecorder {
	t.Helper()
	calls := make([]string, n)
	for i := range calls {
		calls[i] = fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, i+1)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", strings.NewReader(" ["+strings.Join(calls, ",")+"]"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("MCP-Protocol-Version", "2025-03-26")
	rec := httptest.NewRecorder()
	requestPathHandler(c).ServeHTTP(rec, r)
	return rec
}

// A batch at the cap is served whole: every call gets its response.
func TestMCPServerHandler_BatchAtCapServed(t *testing.T) {
	c := createTestCore(t)

	rec := postSysMCPBatch(t, c, maxSysMCPBatch)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var responses []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &responses), "body: %s", rec.Body.String())
	assert.Len(t, responses, maxSysMCPBatch)
}

// A batch over the cap is refused whole, before any call runs, with a 400
// carrying a JSON-RPC Invalid Request error with a null id.
func TestMCPServerHandler_BatchOverCapRefused(t *testing.T) {
	c := createTestCore(t)

	rec := postSysMCPBatch(t, c, maxSysMCPBatch+1)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var refusal struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &refusal), "body: %s", rec.Body.String())
	assert.Equal(t, "2.0", refusal.JSONRPC)
	assert.Equal(t, "null", string(refusal.ID))
	assert.Equal(t, jsonRPCCodeInvalidRequest, refusal.Error.Code)
	assert.Equal(t, fmt.Sprintf("JSON-RPC batch exceeds %d messages", maxSysMCPBatch), refusal.Error.Message)
}

// A single request is never counted against the batch cap.
func TestMCPServerHandler_SingleRequestUnaffectedByBatchCap(t *testing.T) {
	c := createTestCore(t)
	rec := httptest.NewRecorder()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	r := httptest.NewRequest(http.MethodPost, "/v1/sys/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")

	requestPathHandler(c).ServeHTTP(rec, r)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var response map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response), "a single request is answered with a single response")
	assert.EqualValues(t, 1, response["id"])
}
