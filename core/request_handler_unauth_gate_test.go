package core

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
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

// TestStreamUnauthenticatedGate guards the hole opened by letting an empty agent
// mean "the TLS client certificate is the agent", and pins the scope of that
// guard.
//
// The gate is entered on ClientToken == "", which used to imply "no credential
// at all". On a protected-resource mount that is now a routine state, so without
// the cert check a cert-authenticated request carrying a user credential would
// be marked StreamUnauthenticated and skip CheckToken, minting, user capture and
// audit entirely.
//
// The check is deliberately scoped to such mounts. Only there can a cert produce
// an empty agent, and public token-less endpoints must stay reachable from an
// mTLS listener or behind a mesh proxy, where a trusted cert rides every request.
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

	newReq := func(mountPath string, withCert bool) *logical.Request {
		p := mountPath + "gateway/messages"
		hr := httptest.NewRequest(http.MethodPost, "/v1/"+p, nil)
		if withCert {
			hr = hr.WithContext(listener.WithForwardedClientCert(hr.Context(), &x509.Certificate{}))
		}
		return &logical.Request{Path: p, Operation: logical.CreateOperation, HTTPRequest: hr}
	}

	t.Run("protected resource: no credential and no cert is still unauthenticated", func(t *testing.T) {
		req := newReq("protected/", false)
		_, _, _ = core.handleNonLoginRequest(ctx, req)
		assert.True(t, req.StreamUnauthenticated,
			"a genuinely credential-less probe must keep passing through")
	})

	t.Run("protected resource: trusted cert disqualifies the unauthenticated path", func(t *testing.T) {
		req := newReq("protected/", true)
		_, _, _ = core.handleNonLoginRequest(ctx, req)
		assert.False(t, req.StreamUnauthenticated,
			"an empty agent means the cert IS the agent; treating it as unauthenticated "+
				"would skip CheckToken, minting, user capture and audit")
	})

	t.Run("plain mount: a trusted cert does not disqualify it", func(t *testing.T) {
		// 0.19 behaviour, preserved. A cert cannot yield an empty agent here, so
		// an empty ClientToken still means "no credential" — and public
		// token-less endpoints must keep working behind mTLS or a mesh proxy.
		req := newReq("plain/", true)
		_, _, _ = core.handleNonLoginRequest(ctx, req)
		assert.True(t, req.StreamUnauthenticated,
			"scoping the cert check to protected resources keeps non-opted-in mounts byte-identical")
	})
}
