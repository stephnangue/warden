package core

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockUnauthPathBackend declares every path unauthenticated, the way a provider
// with a configured unauthenticated-path pattern behaves. The base
// StreamingBackend implementation is pattern-only and never inspects the
// request, so it cannot itself tell a credential-less probe from a
// cert-authenticated request.
type mockUnauthPathBackend struct {
	mockTransparentModeProvider
	userAuthPath string
}

func (m *mockUnauthPathBackend) IsUnauthenticatedPath(_ *http.Request, _ string) bool { return true }

// GetUserAuthPath makes the mount a protected resource when non-empty, which is
// what turns an empty agent into "the cert is the agent".
func (m *mockUnauthPathBackend) GetUserAuthPath() string { return m.userAuthPath }
func (m *mockUnauthPathBackend) GetUserAuthRole() string { return "" }

// ExtractTokens replaces the base mock's stub, which returns no credentials at
// all. The gate now turns on the extracted user credential, so a stub would
// make every case look credential-less and the test would pass regardless of
// what the gate does.
func (m *mockUnauthPathBackend) ExtractTokens(r *http.Request, userLeg bool) (agent, user string) {
	return logical.ExtractTokensDefault(r, userLeg)
}

// TestStreamUnauthenticatedGate pins what disqualifies a request from
// passthrough: an extracted user credential, not a client certificate.
//
// The gate is entered on ClientToken == "", which used to imply "no credential
// at all". On a protected-resource mount that is now routine, since an empty
// agent there means "the certificate is the agent" — so a request carrying a
// user credential must not be marked StreamUnauthenticated and skip CheckToken,
// minting, user capture and audit.
//
// A certificate alone must not disqualify it. Git's opening info/refs probe is
// exactly that shape — cert agent, no Authorization — and it has to reach the
// upstream to collect the WWW-Authenticate that teaches the client to retry
// with credentials. Gating on the certificate broke every cert-agent git clone.
func TestStreamUnauthenticatedGate(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	mount := func(t *testing.T, path, uuid, userAuthPath string) {
		t.Helper()
		backend := &mockUnauthPathBackend{userAuthPath: userAuthPath}
		entry := &MountEntry{
			Path:        path,
			Type:        "mcp",
			Class:       mountClassProvider,
			UUID:        uuid,
			Accessor:    uuid + "_acc",
			NamespaceID: namespace.RootNamespaceID,
			namespace:   namespace.RootNamespace,
		}
		require.NoError(t, core.router.Mount(path, backend, entry, &mockBarrierView{prefix: "provider/" + uuid + "/"}))
	}
	mount(t, "protected/", "protected-uuid", "auth/user-jwt/")
	mount(t, "plain/", "plain-uuid", "")

	newReq := func(mountPath string, withCert bool, authz string) *logical.Request {
		p := mountPath + "gateway/messages"
		hr := httptest.NewRequest(http.MethodPost, "/v1/"+p, nil)
		if authz != "" {
			hr.Header.Set("Authorization", authz)
		}
		if withCert {
			hr = hr.WithContext(listener.WithForwardedClientCert(hr.Context(), &x509.Certificate{}))
		}
		return &logical.Request{Path: p, Operation: logical.CreateOperation, HTTPRequest: hr}
	}

	t.Run("protected resource: no credential and no cert is still unauthenticated", func(t *testing.T) {
		req := newReq("protected/", false, "")
		_, _, _ = core.handleNonLoginRequest(ctx, req)
		assert.True(t, req.StreamUnauthenticated,
			"a genuinely credential-less probe must keep passing through")
	})

	t.Run("protected resource: a cert with no user credential still passes through", func(t *testing.T) {
		// The git probe shape. Nothing is minted or injected, so the upstream
		// sees an unauthenticated request and answers with the challenge the
		// client needs. Requiring auth here fails for want of a role, because
		// for git the role travels in the Basic username the probe has not sent.
		req := newReq("protected/", true, "")
		_, _, _ = core.handleNonLoginRequest(ctx, req)
		assert.True(t, req.StreamUnauthenticated,
			"a credential-less probe must reach the upstream even under a certificate")
	})

	t.Run("protected resource: a cert plus a user credential disqualifies it", func(t *testing.T) {
		// The actual hazard: passthrough here would skip CheckToken, minting,
		// user capture and audit for a request that carried a principal we are
		// meant to record.
		req := newReq("protected/", true, "Bearer user-jwt")
		_, _, _ = core.handleNonLoginRequest(ctx, req)
		assert.False(t, req.StreamUnauthenticated,
			"a user credential must never be dropped by an unauthenticated-path match")
	})

	t.Run("plain mount: a trusted cert does not disqualify it", func(t *testing.T) {
		// 0.19 behaviour, preserved. A cert cannot yield an empty agent here, so
		// an empty ClientToken still means "no credential" — and public
		// token-less endpoints must keep working behind mTLS or a mesh proxy.
		req := newReq("plain/", true, "")
		_, _, _ = core.handleNonLoginRequest(ctx, req)
		assert.True(t, req.StreamUnauthenticated,
			"non-opted-in mounts stay byte-identical")
	})

	t.Run("plain mount: Authorization is the agent, so it does not disqualify it", func(t *testing.T) {
		// Off the user leg Authorization resolves to the agent, so ClientToken
		// is non-empty and the gate is never entered — the same outcome as 0.19
		// but for the agent's sake, not the user's.
		req := newReq("plain/", false, "Bearer agent-jwt")
		_, _, _ = core.handleNonLoginRequest(ctx, req)
		assert.False(t, req.StreamUnauthenticated,
			"an agent credential off the user leg must still be authenticated")
	})
}

// mcpUnauthPathBackend is the combination no shipped provider produces today:
// a backend that declares its paths unauthenticated AND enforces MCP policy.
// The two are independent opt-ins, so nothing but convention keeps them apart —
// httpproxy's shared backend already implements both interfaces, and only the
// spec hooks decide which providers turn each on.
type mcpUnauthPathBackend struct {
	mockUnauthPathBackend
}

func (m *mcpUnauthPathBackend) ShouldEnforceMCPPolicy(_ *logical.Request) (bool, int64) {
	return true, 1 << 20
}

// TestStreamUnauthenticatedGate_MCPBodyIsRefused pins the guard that keeps an
// MCP-shaped body from skipping policy evaluation entirely.
//
// The unauthenticated streaming path exists for credential-less protocol probes
// and bypasses CheckToken, and with it every gate including the tool contract.
// A JSON-RPC body arriving there would be proxied having answered to nothing —
// precisely the invariant the absence deny exists to hold. It fails closed and
// loudly rather than passing traffic silently, so the day a provider sets both
// hooks it surfaces as a refusal instead of a quiet hole.
func TestStreamUnauthenticatedGate_MCPBodyIsRefused(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	backend := &mcpUnauthPathBackend{}
	entry := &MountEntry{
		Path:        "mcp-unauth/",
		Type:        "mcp",
		Class:       mountClassProvider,
		UUID:        "mcp-unauth-uuid",
		Accessor:    "mcp-unauth-uuid_acc",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}
	require.NoError(t, core.router.Mount("mcp-unauth/", backend, entry,
		&mockBarrierView{prefix: "provider/mcp-unauth-uuid/"}))

	newReq := func(body string) *logical.Request {
		p := "mcp-unauth/gateway/messages"
		hr := httptest.NewRequest(http.MethodPost, "/v1/"+p, strings.NewReader(body))
		hr.Header.Set("Content-Type", "application/json")
		return &logical.Request{Path: p, Operation: logical.CreateOperation, HTTPRequest: hr}
	}

	t.Run("a JSON-RPC body is refused", func(t *testing.T) {
		req := newReq(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"},"id":1}`)
		resp, _, err := core.handleNonLoginRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "unauthenticated streaming paths")
		assert.True(t, req.StreamUnauthenticated,
			"the request did take the unauthenticated path — the guard is what stops it")
	})

	t.Run("a malformed body is refused too", func(t *testing.T) {
		// A parse failure is still a populated descriptor, so it must not slip
		// past on the grounds that no call could be extracted from it.
		req := newReq(`{"jsonrpc":"2.0","method":`)
		resp, _, err := core.handleNonLoginRequest(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Err)
		assert.Contains(t, resp.Err.Error(), "unauthenticated streaming paths")
	})
}
