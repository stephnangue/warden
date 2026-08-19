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
