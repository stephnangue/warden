package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-uuid"
	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Access backends vend credentials in an ordinary response, so their access
// paths are not streaming paths. These tests pin that an agent calling one is
// still authenticated implicitly through the provider's auto_auth_path, exactly
// as on a gateway path, and that everything off that surface is unchanged.

const accessTestJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudC0xIn0.access-sig"

// loginStub is a transparent auth method that admits a fixed set of roles. A
// "jwt" mount logs in the bearer JWT; a "cert" mount logs in the forwarded
// client certificate by fingerprint, as the real methods key their tokens.
type loginStub struct {
	mountType string
	roles     map[string]bool
	delay     time.Duration
	logins    atomic.Int32
}

func (b *loginStub) HandleRequest(_ context.Context, req *logical.Request) (*logical.Response, error) {
	if req.Path != "login" {
		return nil, nil
	}
	b.logins.Add(1)
	if b.delay > 0 {
		time.Sleep(b.delay)
	}
	role, _ := req.Data["role"].(string)
	if !b.roles[role] {
		return logical.ErrorResponse(logical.ErrBadRequestf("role %q could not be found", role)), nil
	}

	auth := &logical.Auth{
		PrincipalID: "agent-1",
		RoleName:    role,
		Policies:    []string{"access-reader"},
		TokenTTL:    time.Hour,
	}
	switch b.mountType {
	case "cert":
		cert := listener.ForwardedClientCert(req.HTTPRequest.Context())
		if cert == nil {
			return logical.ErrorResponse(logical.ErrBadRequest("no client certificate")), nil
		}
		sum := sha256.Sum256(cert.Raw)
		auth.TokenType = TypeCertRole
		auth.ClientToken = hex.EncodeToString(sum[:])
	default:
		auth.TokenType = TypeJWTRole
		auth.ClientToken, _ = req.Data["jwt"].(string)
	}
	return &logical.Response{StatusCode: http.StatusOK, Auth: auth, Data: map[string]any{}}, nil
}

func (b *loginStub) Cleanup(context.Context) {}
func (b *loginStub) Setup(context.Context, *logical.BackendConfig) error {
	return nil
}
func (b *loginStub) Initialize(context.Context) error { return nil }
func (b *loginStub) Config() map[string]any           { return nil }
func (b *loginStub) Type() string                     { return b.mountType }
func (b *loginStub) Class() logical.BackendClass      { return logical.ClassAuth }
func (b *loginStub) HandleExistenceCheck(context.Context, *logical.Request) (bool, bool, error) {
	return false, false, nil
}
func (b *loginStub) SpecialPaths() *logical.Paths {
	return &logical.Paths{Unauthenticated: []string{"login"}}
}
func (b *loginStub) ExtractTokens(*http.Request, bool) (string, string) { return "", "" }

// mountLoginStub mounts a loginStub at auth/<mountType>/ in the root namespace.
func mountLoginStub(t *testing.T, c *Core, mountType string, roles ...string) *loginStub {
	t.Helper()
	stub := &loginStub{mountType: mountType, roles: map[string]bool{}}
	for _, r := range roles {
		stub.roles[r] = true
	}

	accessor, err := c.generateMountAccessor(mountType)
	require.NoError(t, err)
	backendUUID, err := uuid.GenerateUUID()
	require.NoError(t, err)
	mountUUID, err := uuid.GenerateUUID()
	require.NoError(t, err)
	entry := &MountEntry{
		Class:            mountClassAuth,
		Path:             mountType + "/",
		Type:             mountType,
		UUID:             mountUUID,
		Accessor:         accessor,
		BackendAwareUUID: backendUUID,
		NamespaceID:      namespace.RootNamespace.ID,
		namespace:        namespace.RootNamespace,
	}
	view := NewBarrierView(c.barrier, "auth/"+entry.UUID+"/")
	require.NoError(t, c.router.Mount(authRoutePrefix+entry.Path, stub, entry, view))
	c.authLock.Lock()
	c.auth.Entries = append(c.auth.Entries, entry)
	c.authLock.Unlock()
	return stub
}

// accessAuditRecorder records every request and response audit entry.
type accessAuditRecorder struct {
	mockAuditManager
	mu        sync.Mutex
	requests  []*audit.LogEntry
	responses []*audit.LogEntry
}

func (m *accessAuditRecorder) LogRequest(_ context.Context, e *audit.LogEntry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, e)
	return true, nil
}

func (m *accessAuditRecorder) LogResponse(_ context.Context, e *audit.LogEntry) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, e)
	return true, nil
}

// requestFor returns the request audit entry recorded for path.
func (m *accessAuditRecorder) requestFor(t *testing.T, path string) *audit.LogEntry {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.requests {
		if e.Request != nil && e.Request.Path == path {
			return e
		}
	}
	t.Fatalf("no request audit entry for %q", path)
	return nil
}

// accessEnv is a core with an access backend mounted at db/, whose grants
// "ro" and "rw" each mint their own local credential spec.
type accessEnv struct {
	c       *Core
	audit   *accessAuditRecorder
	backend *framework.AccessBackend
}

func newAccessEnv(t *testing.T, autoAuthPath string) *accessEnv {
	t.Helper()
	c := createTestCore(t)
	rec := &accessAuditRecorder{}
	c.auditManager = rec
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	require.NoError(t, c.credConfigStore.CreateSource(ctx, &credential.CredSource{Name: "access-src", Type: "local"}))
	grants := map[string]string{"ro": "access-ro", "rw": "access-rw"}
	for grant, spec := range grants {
		require.NoError(t, c.credConfigStore.CreateSpec(ctx, &credential.CredSpec{
			Name:   spec,
			Type:   credential.TypeAPIKey,
			Source: "access-src",
			Config: credential.NewConfig(map[string]string{"api_key": "secret-for-" + grant}),
		}))
	}

	p := testParsePolicy(t, `path "db/access/*" { capabilities = ["read"] }`)
	p.Name = "access-reader"
	p.Type = PolicyTypeCBP
	require.NoError(t, c.policyStore.SetPolicy(ctx, p, nil))

	b := &framework.AccessBackend{
		Backend: &framework.Backend{
			BackendType:  "dbtest",
			BackendClass: logical.ClassProvider,
		},
	}
	b.Backend.Paths = []*framework.Path{{
		Pattern: "access/(?P<name>[^/]+)",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"role": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: func(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
					grant := d.Get("name").(string)
					spec, ok := grants[grant]
					if !ok {
						return logical.ErrorResponse(logical.ErrNotFoundf("grant %q not found", grant)), nil
					}
					principal := req.TokenEntry().PrincipalID
					return &logical.Response{AccessData: &logical.AccessData{
						CredentialSpec: spec,
						ResponseBuilder: func(cred *credential.Credential) map[string]any {
							return map[string]any{"secret": cred.Data["api_key"], "principal": principal}
						},
					}}, nil
				},
			},
		},
	}}
	view := NewBarrierView(c.barrier, "provider/db-uuid/")
	require.NoError(t, b.Setup(ctx, &logical.BackendConfig{StorageView: view, Logger: c.logger}))
	if autoAuthPath != "" {
		require.NoError(t, b.SetAccessConfig(ctx, &framework.AccessConfig{AutoAuthPath: autoAuthPath}))
	}
	require.NoError(t, c.router.Mount("db/", b, &MountEntry{
		Path:        "db/",
		Type:        "dbtest",
		Class:       mountClassProvider,
		UUID:        "db-uuid",
		Accessor:    "db-acc",
		NamespaceID: namespace.RootNamespaceID,
		namespace:   namespace.RootNamespace,
	}, view))

	return &accessEnv{c: c, audit: rec, backend: b}
}

// get issues GET /v1/<path> with the given headers through the full request
// pipeline, as the HTTP layer would.
func (e *accessEnv) get(t *testing.T, path string, headers map[string]string) (*logical.Response, *logical.Request, error) {
	t.Helper()
	return e.getWithContext(t, path, headers, nil)
}

func (e *accessEnv) getWithContext(t *testing.T, path string, headers map[string]string, wrap func(context.Context) context.Context) (*logical.Response, *logical.Request, error) {
	t.Helper()
	hr := httptest.NewRequest(http.MethodGet, "/v1/"+path, nil)
	if wrap != nil {
		hr = hr.WithContext(wrap(hr.Context()))
	}
	for k, v := range headers {
		hr.Header.Set(k, v)
	}
	reqPath, _, _ := strings.Cut(path, "?")
	req := &logical.Request{
		Path:        reqPath,
		Operation:   logical.ReadOperation,
		HTTPRequest: hr,
		RequestID:   fmt.Sprintf("req-%d", time.Now().UnixNano()),
	}
	resp, err := e.c.HandleRequest(context.Background(), req)
	return resp, req, err
}

func bearer(jwt string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + jwt}
}

func TestAccessPath_ImplicitAuth_JWT(t *testing.T) {
	t.Run("role from the query parameter", func(t *testing.T) {
		env := newAccessEnv(t, "auth/jwt/")
		stub := mountLoginStub(t, env.c, "jwt", "reader")

		resp, req, err := env.get(t, "db/access/ro?role=reader", bearer(accessTestJWT))
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Nil(t, resp.Err, "the agent's JWT must authenticate implicitly, not be read as a Warden token")
		assert.Equal(t, "secret-for-ro", resp.Data["secret"], "the grant's spec is minted")
		assert.Equal(t, "agent-1", resp.Data["principal"])
		assert.True(t, req.Transparent)
		assert.EqualValues(t, 1, stub.logins.Load())

		entry := env.audit.requestFor(t, "db/access/ro")
		require.NotNil(t, entry.Request)
		assert.True(t, entry.Request.Transparent, "the audit records the implicit authentication")
		require.NotNil(t, entry.Auth, "the audit records who was authenticated")
		assert.Equal(t, "agent-1", entry.Auth.PrincipalID)
		assert.Equal(t, "reader", entry.Auth.RoleName)
	})

	t.Run("role from the X-Warden-Role header", func(t *testing.T) {
		env := newAccessEnv(t, "auth/jwt/")
		mountLoginStub(t, env.c, "jwt", "reader")

		headers := bearer(accessTestJWT)
		headers["X-Warden-Role"] = "reader"
		resp, req, err := env.get(t, "db/access/rw", headers)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Nil(t, resp.Err)
		assert.Equal(t, "secret-for-rw", resp.Data["secret"])
		assert.True(t, req.Transparent)
	})

	t.Run("the header overrides the query parameter", func(t *testing.T) {
		env := newAccessEnv(t, "auth/jwt/")
		mountLoginStub(t, env.c, "jwt", "reader")

		headers := bearer(accessTestJWT)
		headers["X-Warden-Role"] = "reader"
		resp, _, err := env.get(t, "db/access/ro?role=unknown", headers)
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Nil(t, resp.Err, "X-Warden-Role wins over ?role=, as on a gateway path")
		assert.Equal(t, "secret-for-ro", resp.Data["secret"])
	})

	t.Run("a refused login answers 401", func(t *testing.T) {
		env := newAccessEnv(t, "auth/jwt/")
		mountLoginStub(t, env.c, "jwt", "reader")

		resp, req, err := env.get(t, "db/access/ro?role=unknown", bearer(accessTestJWT))
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.NotNil(t, resp.Err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the same 401 a gateway path answers")
		assert.True(t, req.Transparent)
		assert.Nil(t, resp.Data["secret"])
	})

	t.Run("a non-JWT bearer answers 401", func(t *testing.T) {
		env := newAccessEnv(t, "auth/jwt/")
		stub := mountLoginStub(t, env.c, "jwt", "reader")

		resp, _, err := env.get(t, "db/access/ro?role=reader", bearer("cws.not-a-jwt"))
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), "requires a JWT bearer token")
		assert.Zero(t, stub.logins.Load())
	})
}

func TestAccessPath_ImplicitAuth_Cert(t *testing.T) {
	env := newAccessEnv(t, "auth/cert/")
	stub := mountLoginStub(t, env.c, "cert", "reader")
	cert, _ := spiffeFakeCert("access-agent-cert-der")
	withCert := func(ctx context.Context) context.Context { return listener.WithForwardedClientCert(ctx, cert) }

	resp, req, err := env.getWithContext(t, "db/access/ro?role=reader", nil, withCert)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Err)
	assert.Equal(t, "secret-for-ro", resp.Data["secret"])
	assert.True(t, req.Transparent)
	assert.EqualValues(t, 1, stub.logins.Load())

	// The second call is served from the cached token, not a fresh login.
	resp, _, err = env.getWithContext(t, "db/access/rw?role=reader", nil, withCert)
	require.NoError(t, err)
	require.Nil(t, resp.Err)
	assert.Equal(t, "secret-for-rw", resp.Data["secret"])
	assert.EqualValues(t, 1, stub.logins.Load())

	t.Run("no certificate answers 401", func(t *testing.T) {
		resp, _, err := env.get(t, "db/access/ro?role=reader", nil)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, resp.Err.Error(), "requires a TLS client certificate")
	})
}

// Without auto_auth_path the provider does not authenticate implicitly: the
// bearer is read as a Warden token, as before.
func TestAccessPath_NoAutoAuthPath_Unchanged(t *testing.T) {
	env := newAccessEnv(t, "")
	stub := mountLoginStub(t, env.c, "jwt", "reader")

	resp, req, err := env.get(t, "db/access/ro?role=reader", bearer(accessTestJWT))
	require.Error(t, err)
	assert.ErrorContains(t, err, sdklogical.ErrPermissionDenied.Error())
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, req.Transparent)
	assert.Zero(t, stub.logins.Load())
}

// An explicit X-Warden-Token is the operator's credential and opts out of
// implicit authentication, on an access path as on a gateway path.
func TestAccessPath_ExplicitWardenToken(t *testing.T) {
	env := newAccessEnv(t, "auth/jwt/")
	stub := mountLoginStub(t, env.c, "jwt", "reader")
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)

	te, err := env.c.tokenStore.GenerateToken(ctx, TypeWardenToken, &AuthData{
		PrincipalID: "operator",
		RoleName:    "ops",
		ExpireAt:    time.Now().Add(time.Hour),
		Policies:    []string{"access-reader"},
	})
	require.NoError(t, err)

	resp, req, err := env.get(t, "db/access/ro", map[string]string{"X-Warden-Token": te.Data["token"]})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Nil(t, resp.Err)
	assert.Equal(t, "secret-for-ro", resp.Data["secret"])
	assert.Equal(t, "operator", resp.Data["principal"])
	assert.False(t, req.Transparent)
	assert.Zero(t, stub.logins.Load())

	t.Run("an unknown token is refused, not logged in", func(t *testing.T) {
		resp, req, err := env.get(t, "db/access/ro", map[string]string{
			"X-Warden-Token": "cws.unknown",
			"Authorization":  "Bearer " + accessTestJWT,
		})
		require.Error(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.False(t, req.Transparent)
		assert.Zero(t, stub.logins.Load())
	})
}

// Off the access surface — the provider's config and grant paths — nothing
// changes: a bearer is still read as a Warden token.
func TestAccessPath_OffSurfaceUnchanged(t *testing.T) {
	env := newAccessEnv(t, "auth/jwt/")
	stub := mountLoginStub(t, env.c, "jwt", "reader")

	_, req, _ := env.get(t, "db/grants/ro?role=reader", bearer(accessTestJWT))
	assert.False(t, req.Transparent)
	assert.Equal(t, accessTestJWT, req.ClientToken)
	assert.Zero(t, stub.logins.Load())
}

// Concurrent first calls with one credential coalesce into one login and share
// its token entry. Each must still mint its own grant's spec: the grant's spec
// is never written into that shared entry.
func TestAccessPath_ConcurrentGrantsShareOneLogin(t *testing.T) {
	env := newAccessEnv(t, "auth/jwt/")
	stub := mountLoginStub(t, env.c, "jwt", "reader")
	stub.delay = 50 * time.Millisecond

	const callers = 16
	var wg sync.WaitGroup
	results := make([]string, callers)
	errs := make([]error, callers)
	for i := range callers {
		grant := "ro"
		if i%2 == 1 {
			grant = "rw"
		}
		wg.Add(1)
		go func(i int, grant string) {
			defer wg.Done()
			resp, _, err := env.get(t, "db/access/"+grant+"?role=reader", bearer(accessTestJWT))
			switch {
			case err != nil:
				errs[i] = err
			case resp == nil || resp.Err != nil:
				errs[i] = fmt.Errorf("grant %s: %v", grant, resp)
			default:
				results[i], _ = resp.Data["secret"].(string)
			}
		}(i, grant)
	}
	wg.Wait()

	for i := range callers {
		require.NoError(t, errs[i])
		want := "secret-for-ro"
		if i%2 == 1 {
			want = "secret-for-rw"
		}
		assert.Equal(t, want, results[i], "caller %d minted another grant's credential", i)
	}
}
