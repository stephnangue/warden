package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// entryCapture records every request and response audit entry.
type entryCapture struct {
	mockAuditManager
	mu      sync.Mutex
	entries []*audit.LogEntry
}

func (m *entryCapture) LogRequest(_ context.Context, e *audit.LogEntry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return true, nil
}

func (m *entryCapture) LogResponse(_ context.Context, e *audit.LogEntry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return true, nil
}

// written is every captured entry as a device would write it, before any salt
// or omit rule.
func (m *entryCapture) written(t *testing.T) []string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.entries))
	for _, e := range m.entries {
		b, err := json.Marshal(e)
		require.NoError(t, err)
		out = append(out, string(b))
	}
	return out
}

// mintingBackend prepares its upstream call the way the gateways do: on the
// request's own header map, replacing the caller's credential with a minted
// one. Its answer carries a secret in its body and headers.
type mintingBackend struct {
	*mockProvider
	handled atomic.Bool
}

func (b *mintingBackend) HandleRequest(_ context.Context, req *logical.Request) (*logical.Response, error) {
	b.handled.Store(true)
	req.HTTPRequest.Header.Set("Authorization", "Bearer MINTED-UPSTREAM-TOKEN")
	req.HTTPRequest.Header.Set("X-Minted", "MINTED-VALUE")
	return &logical.Response{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Set-Cookie": {"session=UPSTREAM-COOKIE"}},
		Data:       map[string]any{"token": "BODY-SECRET"},
	}, nil
}

// Neither the request entry nor the response entry records a credential: not
// the caller's, not the one the backend set on the request's headers while
// handling it, and not the answer's body or headers.
func TestAudit_NoCredentialInRequestOrResponseEntry(t *testing.T) {
	c := createTestCore(t)
	rec := &entryCapture{}
	c.auditManager = rec
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	backend := &mintingBackend{mockProvider: newMockProvider()}
	mountGateway(t, c, "mintgw/", backend)
	root, err := c.tokenStore.GenerateRootToken()
	require.NoError(t, err)

	hr := httptest.NewRequest(http.MethodGet, "/v1/mintgw/creds", nil)
	hr.Header.Set(logical.HeaderWardenToken, root)
	hr.Header.Set("Authorization", "Bearer eyJ.CALLER-JWT")
	resp, err := c.handleCancelableRequest(ctx, &logical.Request{
		Path: "mintgw/creds", Operation: logical.ReadOperation, HTTPRequest: hr,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.True(t, backend.handled.Load(), "the request must reach the backend")

	written := rec.written(t)
	require.Len(t, written, 2, "a request entry and a response entry")
	assert.Contains(t, written[1], `"status_code":200`)
	for _, entry := range written {
		for _, secret := range []string{root, "CALLER-JWT", "MINTED-UPSTREAM-TOKEN", "MINTED-VALUE", "UPSTREAM-COOKIE", "BODY-SECRET"} {
			assert.NotContains(t, entry, secret)
		}
	}
}

// BenchmarkBuildAuditEntries measures the two entries every audited request
// builds, for a gateway call with a typical header set and a small JSON body.
func BenchmarkBuildAuditEntries(b *testing.B) {
	c := &Core{}
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	hr := httptest.NewRequest(http.MethodPost, "/v1/openai/role/agent/gateway/v1/chat/completions", nil)
	for _, h := range []string{"Authorization", "Content-Type", "Accept", "User-Agent", "X-Request-Id", "Traceparent", "Accept-Encoding", "Content-Length"} {
		hr.Header.Set(h, "value-of-"+h)
	}
	req := &logical.Request{
		RequestID: "req-1", Path: "openai/role/agent/gateway/v1/chat/completions",
		Operation: logical.UpdateOperation, HTTPRequest: hr, ClientIP: "10.0.0.1",
		MountPoint: "openai/", MountType: "openai", MountClass: mountClassProvider,
		Data: map[string]any{"model": "gpt", "stream": true, "max_tokens": 512},
	}
	resp := &logical.Response{
		StatusCode: http.StatusOK, Streamed: true,
		Headers: http.Header{"Content-Type": {"application/json"}, "X-Request-Id": {"up-1"}},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.buildRequestAuditEntry(ctx, req, nil, nil, nil)
		_ = c.buildResponseAuditEntry(ctx, req, resp, nil, nil, nil)
	}
}

// The internal login of implicit auth carries the agent's JWT twice: in the
// gateway request's Authorization header, which it shares, and in its own
// body. Neither reaches its audit entry, nor the gateway request's.
func TestAudit_ImplicitLoginRecordsNoJWT(t *testing.T) {
	e := newJWTEnv(t, "")
	e.mount("jwt/", map[string]any{"facts": map[string]any{"sub": "sub"}})
	e.policy("read")
	grantRole(t, e.c, e.ctx, testGrant{Role: "reader", Policies: []string{"read"}, Spec: "read-spec", Mount: "auth/jwt/"})
	rec := &entryCapture{}
	e.c.auditManager = rec

	token := e.token("agent-1", "")
	_, _, err := e.request("jwt/", token, "reader")
	require.NoError(t, err)

	written := rec.written(t)
	require.NotEmpty(t, written, "the internal login is audited")
	for _, entry := range written {
		assert.NotContains(t, entry, token)
	}
}
