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

// TestAmbiguousOperatorAndUserCredentials pins that mixing the operator
// credential with the workload user leg fails loudly.
//
// X-Warden-Token authenticates an agent explicitly — "non-transparent mode" —
// and that stays valid on a gateway path whether or not the mount is a
// protected resource. What is rejected is presenting it *alongside* an
// Authorization credential on a mount with user_auth_path: X-Warden-Token
// carries no user, Authorization is where the user rides, and whichever way a
// provider's precedence falls one of the two is discarded without comment.
func TestAmbiguousOperatorAndUserCredentials(t *testing.T) {
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
	mount(t, "protected/", "amb-protected", "auth/user-jwt/")
	mount(t, "plain/", "amb-plain", "")

	newReq := func(mountPath string, headers map[string]string, cert bool) *logical.Request {
		p := mountPath + "gateway/messages"
		hr := httptest.NewRequest(http.MethodPost, "/v1/"+p, nil)
		for k, v := range headers {
			hr.Header.Set(k, v)
		}
		if cert {
			hr = hr.WithContext(listener.WithForwardedClientCert(hr.Context(), &x509.Certificate{}))
		}
		return &logical.Request{Path: p, Operation: logical.CreateOperation, HTTPRequest: hr}
	}

	isAmbiguityError := func(resp *logical.Response) bool {
		return resp != nil && resp.StatusCode == http.StatusBadRequest &&
			resp.Err != nil && strings.Contains(resp.Err.Error(), "cannot be combined with an Authorization credential")
	}

	t.Run("rejected: operator token plus a bearer on a protected resource", func(t *testing.T) {
		resp, _, _ := core.handleNonLoginRequest(ctx, newReq("protected/", map[string]string{
			"X-Warden-Token": "w", "Authorization": "Bearer u",
		}, false))
		assert.True(t, isAmbiguityError(resp), "the dropped credential must be reported, not swallowed")
	})

	t.Run("rejected: operator token plus a Basic credential", func(t *testing.T) {
		// Git's shape. Basic also rides Authorization, so it is the same clash.
		resp, _, _ := core.handleNonLoginRequest(ctx, newReq("protected/", map[string]string{
			"X-Warden-Token": "w", "Authorization": "Basic cm9sZTpwd2Q=",
		}, false))
		assert.True(t, isAmbiguityError(resp))
	})

	t.Run("allowed: operator token alone on a protected resource", func(t *testing.T) {
		// Explicit (non-transparent) agent auth. Still a supported mode.
		resp, _, _ := core.handleNonLoginRequest(ctx, newReq("protected/", map[string]string{
			"X-Warden-Token": "w",
		}, false))
		assert.False(t, isAmbiguityError(resp))
	})

	t.Run("allowed: operator token plus a bearer on a plain mount", func(t *testing.T) {
		// No user leg, so nothing is dropped — the provider's own precedence
		// decides, exactly as it did before 0.20.
		resp, _, _ := core.handleNonLoginRequest(ctx, newReq("plain/", map[string]string{
			"X-Warden-Token": "w", "Authorization": "Bearer u",
		}, false))
		assert.False(t, isAmbiguityError(resp))
	})

	t.Run("allowed: agent-token header plus a bearer on a protected resource", func(t *testing.T) {
		// The supported two-principal shape.
		resp, _, _ := core.handleNonLoginRequest(ctx, newReq("protected/", map[string]string{
			"X-Warden-Agent-Token": "a", "Authorization": "Bearer u",
		}, false))
		assert.False(t, isAmbiguityError(resp))
	})

	t.Run("allowed: client cert plus a bearer on a protected resource", func(t *testing.T) {
		resp, _, _ := core.handleNonLoginRequest(ctx, newReq("protected/", map[string]string{
			"Authorization": "Bearer u",
		}, true))
		assert.False(t, isAmbiguityError(resp))
	})
}
