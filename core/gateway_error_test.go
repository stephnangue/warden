package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/hashicorp/go-multierror"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderingProvider is a streaming (gateway) provider that renders gateway
// failures, recording what core handed it.
type renderingProvider struct {
	mockTransparentModeProvider
	decline bool
	headers http.Header

	mu    sync.Mutex
	calls int
	got   *logical.GatewayFailure
}

var _ logical.GatewayErrorRenderer = (*renderingProvider)(nil)

// SpecialPaths declares gateway* as streaming, as real providers do, so core
// takes the gateway (streamed) branch for it.
func (p *renderingProvider) SpecialPaths() *logical.Paths {
	return &logical.Paths{Stream: []string{"gateway*"}}
}

func (p *renderingProvider) RenderGatewayError(req *logical.Request, f *logical.GatewayFailure) *logical.Response {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.got = f
	if p.decline {
		return nil
	}
	h := http.Header{"Content-Type": {"text/xml"}}
	for k, v := range p.headers {
		h[k] = v
	}
	return &logical.Response{StatusCode: http.StatusTeapot, Headers: h, Body: []byte("<rendered/>")}
}

// recordingAuditManager captures response audit entries.
type recordingAuditManager struct {
	mockAuditManager
	mu        sync.Mutex
	responses []*audit.LogEntry
}

func (m *recordingAuditManager) LogResponse(_ context.Context, e *audit.LogEntry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, e)
	return true, nil
}

func mountGateway(t *testing.T, c *Core, path string, backend logical.Backend) {
	t.Helper()
	require.NoError(t, c.router.Mount(path, backend, &MountEntry{
		Path:        path,
		Type:        "fake",
		Class:       mountClassProvider,
		UUID:        path + "-uuid",
		Accessor:    path + "acc",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}, &mockBarrierView{prefix: "provider/" + path + "-uuid/"}))
}

// TestRenderGatewayFailure_ThroughCore drives a real gateway failure — a
// transparent-auth failure, one of the two errors seen live — through
// handleCancelableRequest, so the hook's wiring and the audit are both covered:
// the client gets the renderer's answer, and the audit records that same status
// while keeping the original error text.
func TestRenderGatewayFailure_ThroughCore(t *testing.T) {
	c := createTestCore(t)
	rec := &recordingAuditManager{}
	c.auditManager = rec
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// autoAuthPath names a mount that does not exist, so the implicit login fails.
	p := &renderingProvider{mockTransparentModeProvider: mockTransparentModeProvider{
		transparentMode: true, autoAuthPath: "auth/agent-jwt/",
	}}
	mountGateway(t, c, "fakegw/", p)

	hr := httptest.NewRequest(http.MethodGet, "/v1/fakegw/gateway/thing", nil)
	resp, err := c.handleCancelableRequest(ctx, &logical.Request{
		Path: "fakegw/gateway/thing", Operation: logical.ReadOperation,
		HTTPRequest: hr, RequestID: "req-123",
	})

	require.NoError(t, err, "a rendered failure is an answer, not an error for the HTTP layer to format")
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	assert.Equal(t, "<rendered/>", string(resp.Body))
	assert.Equal(t, "text/xml", resp.Headers.Get("Content-Type"))

	require.Equal(t, 1, p.calls)
	assert.Equal(t, logical.GatewayFailureAuth, p.got.Class)
	assert.Equal(t, http.StatusUnauthorized, p.got.Status)
	assert.Equal(t, "req-123", p.got.RequestID)
	require.Error(t, p.got.Err)

	require.Len(t, rec.responses, 1)
	entry := rec.responses[0]
	require.NotNil(t, entry.Response)
	assert.Equal(t, http.StatusTeapot, entry.Response.StatusCode,
		"the audit must record the status the client received")
	assert.Equal(t, p.got.Err.Error(), entry.Error, "the audit must keep the original error text")
}

// TestRenderGatewayFailure_PolicyDenialThroughCore drives the other failure seen
// live, a token the policy check refuses, through handleCancelableRequest, so the
// shape CheckToken really returns (a 403 response and a multierror) is the one
// classified.
func TestRenderGatewayFailure_PolicyDenialThroughCore(t *testing.T) {
	c := createTestCore(t)
	rec := &recordingAuditManager{}
	c.auditManager = rec
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	p := &renderingProvider{}
	mountGateway(t, c, "fakegw/", p)

	hr := httptest.NewRequest(http.MethodGet, "/v1/fakegw/gateway/thing", nil)
	resp, err := c.handleCancelableRequest(ctx, &logical.Request{
		Path: "fakegw/gateway/thing", Operation: logical.ReadOperation,
		HTTPRequest: hr, RequestID: "req-456", ClientToken: "not-a-token",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusTeapot, resp.StatusCode)

	require.Equal(t, 1, p.calls)
	assert.Equal(t, logical.GatewayFailureDenied, p.got.Class)
	assert.Equal(t, http.StatusForbidden, p.got.Status)
	assert.ErrorIs(t, p.got.Err, sdklogical.ErrPermissionDenied)

	require.Len(t, rec.responses, 1)
	assert.Equal(t, http.StatusTeapot, rec.responses[0].Response.StatusCode)
	assert.Equal(t, p.got.Err.Error(), rec.responses[0].Error)
}

// A failure that comes back after routing still finds its renderer: routing
// leaves req.Path relative to the mount, so the hook resolves the backend from
// the path it was handed instead.
func TestRenderGatewayFailure_AfterRouting(t *testing.T) {
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	p := &renderingProvider{}
	mountGateway(t, c, "fakegw/", p)

	req := &logical.Request{Path: "fakegw/gateway/x", Streamed: true, RequestID: "rid"}
	_, err := c.doRouting(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "gateway/x", req.Path, "routing leaves req.Path relative to the mount")

	out, err := c.renderGatewayFailure(ctx, req, "fakegw/gateway/x",
		logical.ErrorResponse(logical.ErrBadRequest("failed after routing")), nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTeapot, out.StatusCode)
	assert.Equal(t, 1, p.calls)
}

// TestRenderGatewayFailure_Classes drives each failure shape core produces for a
// gateway request, and checks the renderer is handed the right class and status.
func TestRenderGatewayFailure_Classes(t *testing.T) {
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	p := &renderingProvider{}
	mountGateway(t, c, "fakegw/", p)
	req := func() *logical.Request {
		return &logical.Request{Path: "fakegw/gateway/x", Streamed: true, RequestID: "rid"}
	}

	issue := &logical.CredentialIssueError{Spec: "s", Err: errors.New("upstream said no")}
	for _, tc := range []struct {
		name       string
		resp       *logical.Response
		err        error
		wantClass  logical.GatewayFailureClass
		wantStatus int
	}{
		{
			// CheckToken's shape: a 403 response AND a multierror-wrapped sentinel.
			name:       "policy denial (error exit)",
			resp:       logical.ErrorResponse(sdklogical.ErrPermissionDenied),
			err:        multierror.Append(nil, sdklogical.ErrPermissionDenied),
			wantClass:  logical.GatewayFailureDenied,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "transparent auth (response exit)",
			resp:       logical.ErrorResponse(logical.ErrUnauthorized("bad jwt")),
			wantClass:  logical.GatewayFailureAuth,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "credential issuance (response exit)",
			resp:       logical.ErrorResponse(issue),
			wantClass:  logical.GatewayFailureMint,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "bad request",
			resp:       logical.ErrorResponse(logical.ErrBadRequest("no spec bound")),
			wantClass:  logical.GatewayFailureBadRequest,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "internal error",
			err:        ErrInternalError,
			wantClass:  logical.GatewayFailureInternal,
			wantStatus: http.StatusInternalServerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := c.renderGatewayFailure(ctx, req(), "fakegw/gateway/x", tc.resp, tc.err)
			require.NoError(t, err)
			require.NotNil(t, out)
			assert.Equal(t, http.StatusTeapot, out.StatusCode)
			assert.Equal(t, tc.wantClass, p.got.Class)
			assert.Equal(t, tc.wantStatus, p.got.Status)
			assert.Equal(t, "rid", p.got.RequestID)
			// The original error is kept on the answer, for the audit.
			assert.Equal(t, p.got.Err, out.Err)
		})
	}
}

// Headers core attached to the original answer (a challenge, say) survive, but
// the renderer wins where it set the same header.
func TestRenderGatewayFailure_MergesHeaders(t *testing.T) {
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	p := &renderingProvider{headers: http.Header{"X-Both": {"renderer"}}}
	mountGateway(t, c, "fakegw/", p)

	orig := logical.ErrorResponse(logical.ErrUnauthorized("bad jwt"))
	orig.Headers = http.Header{
		"Www-Authenticate": {`Basic realm="warden"`},
		"X-Both":           {"core"},
	}
	out, err := c.renderGatewayFailure(ctx,
		&logical.Request{Path: "fakegw/gateway/x", Streamed: true}, "fakegw/gateway/x", orig, nil)
	require.NoError(t, err)
	assert.Equal(t, `Basic realm="warden"`, out.Headers.Get("WWW-Authenticate"))
	assert.Equal(t, "renderer", out.Headers.Get("X-Both"))
	assert.Equal(t, "text/xml", out.Headers.Get("Content-Type"))
}

// Everything the hook must leave alone, returned exactly as given and with the
// renderer not consulted where it has no business being.
func TestRenderGatewayFailure_NoOps(t *testing.T) {
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	p := &renderingProvider{}
	mountGateway(t, c, "fakegw/", p)
	mountGateway(t, c, "plaingw/", &mockProvider{}) // does not implement the renderer
	declining := &renderingProvider{decline: true}
	mountGateway(t, c, "declinegw/", declining)

	failure := logical.ErrorResponse(logical.ErrUnauthorized("bad jwt"))
	for _, tc := range []struct {
		name string
		req  *logical.Request
		resp *logical.Response
		err  error
	}{
		{"not a gateway request", &logical.Request{Path: "fakegw/config"}, failure, nil},
		{"backend already wrote the response",
			&logical.Request{Path: "fakegw/gateway/x", Streamed: true},
			&logical.Response{Streamed: true, StatusCode: http.StatusBadGateway}, nil},
		{"standby redirect must reach the HTTP layer",
			&logical.Request{Path: "fakegw/gateway/x", Streamed: true}, nil, fmt.Errorf("wrap: %w", ErrStandby)},
		{"success", &logical.Request{Path: "fakegw/gateway/x", Streamed: true},
			&logical.Response{StatusCode: http.StatusOK}, nil},
		{"no response and no error", &logical.Request{Path: "fakegw/gateway/x", Streamed: true}, nil, nil},
		{"backend does not render",
			&logical.Request{Path: "plaingw/gateway/x", Streamed: true}, failure, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := p.calls
			out, err := c.renderGatewayFailure(ctx, tc.req, tc.req.Path, tc.resp, tc.err)
			assert.Same(t, tc.resp, out)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, before, p.calls, "the renderer must not be consulted")
		})
	}

	t.Run("renderer declines", func(t *testing.T) {
		out, err := c.renderGatewayFailure(ctx,
			&logical.Request{Path: "declinegw/gateway/x", Streamed: true}, "declinegw/gateway/x", failure, nil)
		assert.Same(t, failure, out)
		assert.NoError(t, err)
		assert.Equal(t, 1, declining.calls, "consulted, and its nil respected")
	})
}
