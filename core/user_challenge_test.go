package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestErrUserRequiredMapsTo401 pins the status the whole bootstrap depends on.
// Clients begin metadata discovery on a 401 specifically; at 400 or 500 a
// spec-compliant client stops, and the challenge never gets read.
func TestErrUserRequiredMapsTo401(t *testing.T) {
	assert.Equal(t, http.StatusUnauthorized, logical.GetErrorCode(credential.ErrUserRequired))

	// It must survive the wrapping it actually travels through: the mint path
	// wraps with %w, and errors.Is traverses any depth.
	wrapped := fmt.Errorf("failed to issue credential: %w",
		fmt.Errorf("spec %q: %w", "s", credential.ErrUserRequired))
	assert.Equal(t, http.StatusUnauthorized, logical.GetErrorCode(wrapped))
	assert.Equal(t, http.StatusUnauthorized, logical.ErrorResponse(wrapped).StatusCode)
}

// TestInputResolutionStatusCodes guards the regression the conditional wrap
// exists to prevent. Returning the error un-coded would push the non-user
// failures from 400 to 500; coding them all 400 would mask the 401.
func TestInputResolutionStatusCodes(t *testing.T) {
	t.Run("missing user is 401", func(t *testing.T) {
		got := exchangeInputError(fmt.Errorf("spec %q: %w", "s", credential.ErrUserRequired))
		assert.Equal(t, http.StatusUnauthorized, logical.GetErrorCode(got))
		assert.ErrorIs(t, got, credential.ErrUserRequired,
			"the sentinel must survive so the challenge can be attached downstream")
	})

	t.Run("every other resolution failure stays 400", func(t *testing.T) {
		got := exchangeInputError(fmt.Errorf("unsupported subject_token_source"))
		assert.Equal(t, http.StatusBadRequest, logical.GetErrorCode(got),
			"a malformed spec is not something a client fixes by authenticating")
	})

	t.Run("a plain error never falls through to 500", func(t *testing.T) {
		// Returning the error un-coded would regress every non-user failure from
		// 400 to 500, since GetErrorCode has no rule for a bare error.
		assert.Equal(t, http.StatusInternalServerError,
			logical.GetErrorCode(fmt.Errorf("bare")),
			"guards the assumption the 400 branch exists to satisfy")
	})
}

// challengeTestCore mounts an opted-in mount and a plain one, and optionally
// enables metadata. Mirrors prmTestCore so a challenge and the document it names
// are produced from the same shape.
func challengeTestCore(t *testing.T, enabled bool) *Core {
	t.Helper()
	core := createTestCore(t)

	mount := func(path, uuid, userAuthPath string) {
		entry := &MountEntry{
			Path: path, Type: "mcp", Class: mountClassProvider,
			UUID: uuid, Accessor: uuid + "_acc",
			NamespaceID: namespace.RootNamespaceID, namespace: namespace.RootNamespace,
		}
		require.NoError(t, core.router.Mount(path,
			&mockUnauthPathBackend{userAuthPath: userAuthPath}, entry,
			&mockBarrierView{prefix: "provider/" + uuid + "/"}))
	}
	mount("github/", "chal-gh", "auth/user-jwt/")
	mount("plain/", "chal-plain", "")

	if enabled {
		view := NewBarrierView(core.barrier, protectedResourceStorePrefix)
		require.NoError(t, saveProtectedResourceConfig(context.Background(), view,
			&protectedResourceConfig{
				ResourceURL:          "https://warden.example.com",
				AuthorizationServers: []string{"https://idp.example.com"},
			}))
	}
	return core
}

func TestPRMMetadataURL(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	t.Run("empty when metadata is not configured", func(t *testing.T) {
		assert.Empty(t, challengeTestCore(t, false).prmMetadataURL(ctx, "github/"))
	})

	t.Run("built from the configured external base", func(t *testing.T) {
		assert.Equal(t,
			"https://warden.example.com/.well-known/oauth-protected-resource/v1/github",
			challengeTestCore(t, true).prmMetadataURL(ctx, "github/"))
	})

	t.Run("empty for a mount the endpoint would not serve", func(t *testing.T) {
		// The plain mount has no user_auth_path, so the metadata endpoint 404s
		// it. Naming that URL would send the client to a dead document and kill
		// the bootstrap silently — worse than sending no challenge at all.
		assert.Empty(t, challengeTestCore(t, true).prmMetadataURL(ctx, "plain/"),
			"the challenge must not name a URL that 404s")
	})

	t.Run("empty for an unknown mount", func(t *testing.T) {
		assert.Empty(t, challengeTestCore(t, true).prmMetadataURL(ctx, "nope/"))
	})

	t.Run("empty for a request with no mount", func(t *testing.T) {
		assert.Empty(t, challengeTestCore(t, true).prmMetadataURL(ctx, ""))
	})
}

// TestAccessPathMintError pins that a user requirement on the access path is
// reported as the operator misconfiguration it is, not as a 401.
//
// AccessData comes only from non-streaming backends, where captureUserContext
// never runs, so req.User is structurally nil on every such request. A 401 there
// would tell a client to authenticate when it already has, and no retry could
// ever change the outcome.
func TestAccessPathMintError(t *testing.T) {
	t.Run("a missing user becomes a server-side error", func(t *testing.T) {
		got := accessPathMintError(fmt.Errorf("mint: %w", credential.ErrUserRequired))
		assert.Equal(t, http.StatusInternalServerError, logical.GetErrorCode(got),
			"401 would invite a retry that cannot succeed on this path")
		assert.Contains(t, got.Error(), "access-path requests cannot carry one",
			"the message must reach an operator, not send a client round a loop")
	})

	t.Run("every other error passes through untouched", func(t *testing.T) {
		orig := logical.ErrBadRequest("malformed spec")
		assert.Same(t, orig, accessPathMintError(orig))
	})
}

// TestChallengeURLIsActuallyServed is the anti-drift check: the URL a challenge
// names must be one the metadata endpoint resolves. The two are derived
// independently, and a mismatch fails silently — the client follows the link,
// gets a 404, and never learns where to authenticate.
func TestChallengeURLIsActuallyServed(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	core := challengeTestCore(t, true)

	url := core.prmMetadataURL(ctx, "github/")
	require.NotEmpty(t, url)

	const base = "https://warden.example.com" + PRMWellKnownPath
	require.True(t, len(url) > len(base) && url[:len(base)] == base)
	suffix := url[len(base):]

	body, _, err := core.ProtectedResourceMetadata(ctx, suffix)
	require.NoError(t, err, "the endpoint must serve exactly the suffix the challenge names")
	assert.NotEmpty(t, body)
}

// TestChallengeURLInChildNamespace covers the ns.Path + mountPoint concatenation,
// which is the part of the URL that would drift silently: the root namespace has
// an empty path, so a bug there is invisible until a real namespace is used.
func TestChallengeURLInChildNamespace(t *testing.T) {
	core := createTestCore(t)

	// Namespaces are created from the root context; the store assigns ID/UUID.
	rootCtx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	child := &namespace.Namespace{Path: "team-a/"}
	require.NoError(t, core.namespaceStore.SetNamespace(rootCtx, child))

	ctx := namespace.ContextWithNamespace(context.Background(), child)

	entry := &MountEntry{
		Path: "github/", Type: "mcp", Class: mountClassProvider,
		UUID: "ns-gh", Accessor: "ns-gh_acc",
		NamespaceID: child.ID, namespace: child,
	}
	// Mount prepends the entry's namespace path itself, so the prefix here is
	// namespace-relative.
	require.NoError(t, core.router.Mount("github/",
		&mockUnauthPathBackend{userAuthPath: "auth/user-jwt/"}, entry,
		&mockBarrierView{prefix: "provider/ns-gh/"}))

	view := NewBarrierView(core.barrier, protectedResourceStorePrefix)
	require.NoError(t, saveProtectedResourceConfig(ctx, view,
		&protectedResourceConfig{
			ResourceURL:          "https://warden.example.com",
			AuthorizationServers: []string{"https://idp.example.com"},
		}))

	assert.Equal(t,
		"https://warden.example.com"+PRMWellKnownPath+"/v1/team-a/github",
		core.prmMetadataURL(ctx, "github/"),
		"the namespace must appear in the URL exactly once, matching what the endpoint serves")
}

func TestAttachUserChallenge(t *testing.T) {
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	newReq := func(path, mount string) *logical.Request {
		return &logical.Request{
			Path:        path,
			MountPoint:  mount,
			HTTPRequest: httptest.NewRequest(http.MethodGet, "/v1/"+path, nil),
		}
	}

	t.Run("points at the mount's metadata", func(t *testing.T) {
		resp := logical.ErrorResponse(logical.ErrUnauthorized("nope"))
		challengeTestCore(t, true).attachUserChallenge(ctx, newReq("github/gateway/user", "github/"), resp, false)

		got := resp.Headers.Get("WWW-Authenticate")
		assert.Equal(t,
			`Bearer resource_metadata="https://warden.example.com/.well-known/oauth-protected-resource/v1/github"`,
			got)
		assert.NotContains(t, got, "invalid_token",
			"no credential was presented, so naming one invalid would be a lie")
	})

	t.Run("a rejected credential is marked invalid_token", func(t *testing.T) {
		resp := logical.ErrorResponse(logical.ErrUnauthorized("nope"))
		challengeTestCore(t, true).attachUserChallenge(ctx, newReq("github/gateway/user", "github/"), resp, true)
		assert.Contains(t, resp.Headers.Get("WWW-Authenticate"), `error="invalid_token"`)
	})

	t.Run("git smart-HTTP also gets a Basic challenge", func(t *testing.T) {
		// A bare Bearer challenge is unactionable for git, which negotiates with
		// Basic. RFC 9110 permits multiple challenges.
		resp := logical.ErrorResponse(logical.ErrUnauthorized("nope"))
		challengeTestCore(t, true).attachUserChallenge(ctx,
			newReq("github/gateway/o/r.git/info/refs", "github/"), resp, false)

		got := resp.Headers.Get("WWW-Authenticate")
		assert.Contains(t, got, `Basic realm="warden"`)
		assert.Contains(t, got, "resource_metadata=")
	})

	t.Run("a non-gateway path ending in a git suffix gets no Basic challenge", func(t *testing.T) {
		// IsSmartHTTPPath is a pure suffix match, so the gateway segment has to
		// be checked too or any such path draws a spurious Basic challenge.
		resp := logical.ErrorResponse(logical.ErrUnauthorized("nope"))
		challengeTestCore(t, true).attachUserChallenge(ctx,
			newReq("github/config/o/r.git/info/refs", "github/"), resp, false)
		assert.NotContains(t, resp.Headers.Get("WWW-Authenticate"), "Basic")
	})

	// RFC 7235 requires a challenge on every 401, so the scheme is always
	// emitted — but resource_metadata is omitted whenever no document would be
	// served, since a client that follows a 404 learns nothing and the bootstrap
	// dies silently.
	t.Run("metadata not configured: bare challenge, no URL", func(t *testing.T) {
		resp := logical.ErrorResponse(logical.ErrUnauthorized("nope"))
		challengeTestCore(t, false).attachUserChallenge(ctx, newReq("github/gateway/user", "github/"), resp, false)

		got := resp.Headers.Get("WWW-Authenticate")
		assert.Equal(t, "Bearer", got)
		assert.NotContains(t, got, "resource_metadata")
	})

	t.Run("mount not a protected resource: bare challenge, no URL", func(t *testing.T) {
		resp := logical.ErrorResponse(logical.ErrUnauthorized("nope"))
		challengeTestCore(t, true).attachUserChallenge(ctx, newReq("plain/gateway/x", "plain/"), resp, false)

		got := resp.Headers.Get("WWW-Authenticate")
		assert.NotContains(t, got, "resource_metadata",
			"a mount with no user_auth_path serves no document, so there is nothing to name")
		assert.Contains(t, got, "Bearer", "a 401 must still carry a challenge")
	})

	t.Run("invalid token with no servable metadata still reports the cause", func(t *testing.T) {
		resp := logical.ErrorResponse(logical.ErrUnauthorized("nope"))
		challengeTestCore(t, false).attachUserChallenge(ctx, newReq("github/gateway/user", "github/"), resp, true)

		got := resp.Headers.Get("WWW-Authenticate")
		assert.Equal(t, `Bearer error="invalid_token"`, got)
	})

	t.Run("only the missing-user error draws a challenge", func(t *testing.T) {
		core := challengeTestCore(t, true)
		req := newReq("github/gateway/user", "github/")

		userErr := logical.ErrorResponse(fmt.Errorf("mint: %w", credential.ErrUserRequired))
		core.attachUserRequiredChallenge(ctx, req, userErr, fmt.Errorf("mint: %w", credential.ErrUserRequired))
		assert.NotEmpty(t, userErr.Headers.Get("WWW-Authenticate"))

		// An unreachable upstream is not fixed by acquiring a user identity, so
		// sending the client on an OAuth round trip would be pointless.
		otherErr := logical.ErrorResponse(fmt.Errorf("upstream unreachable"))
		core.attachUserRequiredChallenge(ctx, req, otherErr, fmt.Errorf("upstream unreachable"))
		assert.Empty(t, otherErr.Headers.Get("WWW-Authenticate"))
	})
}

// TestAttachGitBasicChallenge covers the transparent-auth failure, which is a
// different 401 from the user-required one: the agent is what failed, so there
// is no metadata pointer to offer. On git the client can still fix it by
// retrying with Basic, which is where the role and any user credential ride.
//
// Reached only when an out-of-band agent forced authentication. A probe with no
// agent at all passes through and collects the upstream's own challenge.
func TestAttachGitBasicChallenge(t *testing.T) {
	newReq := func(path string) *logical.Request {
		return &logical.Request{
			Path:        path,
			MountPoint:  "github/",
			HTTPRequest: httptest.NewRequest(http.MethodGet, "/v1/"+path, nil),
		}
	}

	t.Run("git smart-HTTP gets a Basic challenge", func(t *testing.T) {
		resp := logical.ErrorResponse(logical.ErrUnauthorized("missing role"))
		attachGitBasicChallenge(newReq("github/gateway/o/r.git/info/refs"), resp)
		assert.Equal(t, `Basic realm="warden"`, resp.Headers.Get("WWW-Authenticate"))
	})

	t.Run("no Bearer scheme is offered", func(t *testing.T) {
		// Advertising the user leg here would send the client to acquire an
		// identity that cannot fix an agent failure.
		resp := logical.ErrorResponse(logical.ErrUnauthorized("missing role"))
		attachGitBasicChallenge(newReq("github/gateway/o/r.git/git-upload-pack"), resp)
		assert.NotContains(t, resp.Headers.Get("WWW-Authenticate"), "Bearer")
	})

	t.Run("a non-git gateway path gets no challenge", func(t *testing.T) {
		resp := logical.ErrorResponse(logical.ErrUnauthorized("missing role"))
		attachGitBasicChallenge(newReq("github/gateway/user"), resp)
		assert.Empty(t, resp.Headers.Get("WWW-Authenticate"))
	})

	t.Run("a non-gateway path ending in a git suffix gets none either", func(t *testing.T) {
		resp := logical.ErrorResponse(logical.ErrUnauthorized("missing role"))
		attachGitBasicChallenge(newReq("github/config/o/r.git/info/refs"), resp)
		assert.Empty(t, resp.Headers.Get("WWW-Authenticate"))
	})

	t.Run("nil arguments are inert", func(t *testing.T) {
		assert.NotPanics(t, func() {
			attachGitBasicChallenge(nil, logical.ErrorResponse(logical.ErrUnauthorized("x")))
			attachGitBasicChallenge(newReq("github/gateway/o/r.git/info/refs"), nil)
		})
	})
}

// TestTransparentAuthFailureCarriesGitChallenge pins the wiring rather than the
// helper. A request that reaches transparent auth was not passed through, so no
// upstream response will be relayed and this 401 is the only thing that can tell
// the client to retry with credentials. Without the header git simply gives up.
func TestTransparentAuthFailureCarriesGitChallenge(t *testing.T) {
	core := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	// autoAuthPath names a mount that does not exist, so the implicit login
	// fails — standing in for the real failure, a probe with no resolvable role.
	backend := &mockTransparentModeProvider{transparentMode: true, autoAuthPath: "auth/agent-jwt/"}
	require.NoError(t, core.router.Mount("github/", backend, &MountEntry{
		Path:        "github/",
		Type:        "github",
		Class:       mountClassProvider,
		UUID:        "github-challenge-uuid",
		Accessor:    "github_challenge_acc",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}, &mockBarrierView{prefix: "provider/github-challenge-uuid/"}))

	handle := func(t *testing.T, path string) *logical.Response {
		t.Helper()
		hr := httptest.NewRequest(http.MethodGet, "/v1/"+path, nil)
		resp, _, _ := core.handleNonLoginRequest(ctx,
			&logical.Request{Path: path, Operation: logical.ReadOperation, HTTPRequest: hr})
		require.NotNil(t, resp)
		return resp
	}

	t.Run("git smart-HTTP failure carries the Basic challenge", func(t *testing.T) {
		resp := handle(t, "github/gateway/o/r.git/info/refs")
		assert.Equal(t, `Basic realm="warden"`, resp.Headers.Get("WWW-Authenticate"))
	})

	t.Run("a non-git failure carries none", func(t *testing.T) {
		resp := handle(t, "github/gateway/user")
		assert.Empty(t, resp.Headers.Get("WWW-Authenticate"),
			"only git needs telling which scheme to retry with")
	})
}
