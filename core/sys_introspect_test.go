// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/listener"
	"github.com/stephnangue/warden/logical"
)

// introspectMock is a per-test controller for the mock auth backend. Each
// test instantiates its own controller and registers its factory, so
// tests do not share mutable state and can run in parallel if desired.
// Map keys are the router-visible mount paths (e.g. "auth/jwt-a/") that
// appear on logical.Request.MountPoint inside HandleRequest.
type introspectMock struct {
	rolesByMount       map[string][]map[string]any
	errsByMount        map[string]error
	delayByMount       map[string]time.Duration
	unsupportedByMount map[string]bool
}

func newIntrospectMock() *introspectMock {
	return &introspectMock{
		rolesByMount:       map[string][]map[string]any{},
		errsByMount:        map[string]error{},
		delayByMount:       map[string]time.Duration{},
		unsupportedByMount: map[string]bool{},
	}
}

func (m *introspectMock) factory() logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		return &introspectMockBackend{ctrl: m}, nil
	}
}

type introspectMockBackend struct {
	ctrl *introspectMock
}

func (b *introspectMockBackend) HandleRequest(ctx context.Context, req *logical.Request) (*logical.Response, error) {
	if req.Path != "introspect/roles" {
		return nil, nil
	}
	if d := b.ctrl.delayByMount[req.MountPoint]; d > 0 {
		time.Sleep(d)
	}
	if b.ctrl.unsupportedByMount[req.MountPoint] {
		return nil, sdklogical.ErrUnsupportedPath
	}
	if err := b.ctrl.errsByMount[req.MountPoint]; err != nil {
		return nil, err
	}
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"roles": b.ctrl.rolesByMount[req.MountPoint],
		},
	}, nil
}

func (b *introspectMockBackend) Cleanup(ctx context.Context)                               {}
func (b *introspectMockBackend) Setup(ctx context.Context, c *logical.BackendConfig) error { return nil }
func (b *introspectMockBackend) Initialize(ctx context.Context) error                      { return nil }
func (b *introspectMockBackend) Config() map[string]any                                    { return nil }
func (b *introspectMockBackend) Type() string                                              { return "jwt" }
func (b *introspectMockBackend) Class() logical.BackendClass                               { return logical.ClassAuth }
func (b *introspectMockBackend) HandleExistenceCheck(ctx context.Context, req *logical.Request) (bool, bool, error) {
	return false, false, nil
}
func (b *introspectMockBackend) SpecialPaths() *logical.Paths        { return nil }
func (b *introspectMockBackend) ExtractToken(r *http.Request) string { return "" }

// jwtRequest builds a system-backend request with an Authorization: Bearer
// header, which the aggregator interprets as credType = "jwt".
func jwtRequest(t *testing.T) *logical.Request {
	t.Helper()
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/sys/introspect/roles", nil)
	httpReq.Header.Set("Authorization", "Bearer eyJ.any.token")
	return &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "introspect/roles",
		HTTPRequest: httpReq,
	}
}

// certRequest builds a system-backend request carrying a forwarded
// client certificate in the HTTP request context, which the aggregator
// interprets as credType = "cert".
func certRequest(t *testing.T) *logical.Request {
	t.Helper()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
	}
	httpReq := httptest.NewRequest(http.MethodGet, "/v1/sys/introspect/roles", nil)
	ctx := listener.WithForwardedClientCert(httpReq.Context(), cert)
	httpReq = httpReq.WithContext(ctx)
	return &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "introspect/roles",
		HTTPRequest: httpReq,
	}
}

func TestDetectIntrospectCredType(t *testing.T) {
	t.Run("no HTTP request returns empty", func(t *testing.T) {
		assert.Equal(t, "", detectIntrospectCredType(&logical.Request{}))
	})
	t.Run("Authorization: Bearer returns jwt", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodGet, "/x", nil)
		httpReq.Header.Set("Authorization", "Bearer eyJ.abc.def")
		assert.Equal(t, "jwt", detectIntrospectCredType(&logical.Request{HTTPRequest: httpReq}))
	})
	t.Run("no Bearer prefix returns empty", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodGet, "/x", nil)
		httpReq.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		assert.Equal(t, "", detectIntrospectCredType(&logical.Request{HTTPRequest: httpReq}))
	})
	t.Run("forwarded client cert returns cert (takes precedence over JWT)", func(t *testing.T) {
		cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "c"}}
		httpReq := httptest.NewRequest(http.MethodGet, "/x", nil)
		httpReq.Header.Set("Authorization", "Bearer eyJ.abc.def")
		ctx := listener.WithForwardedClientCert(httpReq.Context(), cert)
		httpReq = httpReq.WithContext(ctx)
		assert.Equal(t, "cert", detectIntrospectCredType(&logical.Request{HTTPRequest: httpReq}))
	})
}

func TestSystemBackend_Introspect_Unauthenticated(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	resp, err := backend.handleIntrospectRoles(ctx, &logical.Request{}, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.NotNil(t, resp.Err)
}

func TestSystemBackend_Introspect_NoMatchingMounts(t *testing.T) {
	backend, ctx, _ := setupTestSystemBackend(t)

	// No auth mounts exist — aggregator should return an empty list, not error.
	resp, err := backend.handleIntrospectRoles(ctx, jwtRequest(t), nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	roles := resp.Data["roles"].([]aggregatedRole)
	assert.Empty(t, roles)
	warnings := resp.Data["warnings"].([]string)
	assert.Empty(t, warnings)
}

func TestSystemBackend_Introspect_JWTFanOut(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()

	core.authMethods["jwt"] = ctrl.factory()
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt-a/"}))
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt-b/"}))

	ctrl.rolesByMount["auth/jwt-a/"] = []map[string]any{
		{"name": "reader", "description": "read prod"},
		{"name": "admin"},
	}
	ctrl.rolesByMount["auth/jwt-b/"] = []map[string]any{
		{"name": "writer", "description": "write staging"},
	}

	resp, err := backend.handleIntrospectRoles(ctx, jwtRequest(t), nil)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	roles := resp.Data["roles"].([]aggregatedRole)
	require.Len(t, roles, 3)
	// Sorted by auth_path, then name.
	assert.Equal(t, "jwt-a/", roles[0].AuthPath)
	assert.Equal(t, "admin", roles[0].Name)
	assert.Equal(t, "jwt-a/", roles[1].AuthPath)
	assert.Equal(t, "reader", roles[1].Name)
	assert.Equal(t, "read prod", roles[1].Description)
	assert.Equal(t, "jwt-b/", roles[2].AuthPath)
	assert.Equal(t, "writer", roles[2].Name)

	warnings := resp.Data["warnings"].([]string)
	assert.Empty(t, warnings)
}

func TestSystemBackend_Introspect_FilterByCredType(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()

	// Register the same factory under both "jwt" and "cert" so we can
	// verify the aggregator only targets the matching credential type.
	core.authMethods["jwt"] = ctrl.factory()
	core.authMethods["cert"] = ctrl.factory()
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "jwt-mount/"}))
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "cert", Path: "cert-mount/"}))

	ctrl.rolesByMount["auth/jwt-mount/"] = []map[string]any{{"name": "jwt-role"}}
	ctrl.rolesByMount["auth/cert-mount/"] = []map[string]any{{"name": "cert-role"}}

	// JWT request should only hit the JWT mount.
	resp, err := backend.handleIntrospectRoles(ctx, jwtRequest(t), nil)
	require.NoError(t, err)
	roles := resp.Data["roles"].([]aggregatedRole)
	require.Len(t, roles, 1)
	assert.Equal(t, "jwt-role", roles[0].Name)
	assert.Equal(t, "jwt-mount/", roles[0].AuthPath)

	// Cert request should only hit the cert mount.
	resp, err = backend.handleIntrospectRoles(ctx, certRequest(t), nil)
	require.NoError(t, err)
	roles = resp.Data["roles"].([]aggregatedRole)
	require.Len(t, roles, 1)
	assert.Equal(t, "cert-role", roles[0].Name)
	assert.Equal(t, "cert-mount/", roles[0].AuthPath)
}

func TestSystemBackend_Introspect_MountError_AppearsInWarnings(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()

	core.authMethods["jwt"] = ctrl.factory()
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "good/"}))
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "bad/"}))

	ctrl.rolesByMount["auth/good/"] = []map[string]any{{"name": "ok-role"}}
	ctrl.errsByMount["auth/bad/"] = fmt.Errorf("storage unavailable")

	resp, err := backend.handleIntrospectRoles(ctx, jwtRequest(t), nil)
	require.NoError(t, err)

	// The working mount's roles still come through.
	roles := resp.Data["roles"].([]aggregatedRole)
	require.Len(t, roles, 1)
	assert.Equal(t, "ok-role", roles[0].Name)
	assert.Equal(t, "good/", roles[0].AuthPath)

	// The broken mount appears in warnings.
	warnings := resp.Data["warnings"].([]string)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "bad/")
	assert.Contains(t, warnings[0], "storage unavailable")
}

// A backend that returns ErrUnsupportedPath for introspect/roles simulates
// an older auth method that hasn't been upgraded to expose introspection.
// These mounts must be silently skipped (no warning, no failure) so that
// adding introspection support can roll out incrementally across backends.
func TestSystemBackend_Introspect_SkipsMountsWithoutIntrospect(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()

	core.authMethods["jwt"] = ctrl.factory()
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "modern/"}))
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "legacy/"}))

	ctrl.rolesByMount["auth/modern/"] = []map[string]any{{"name": "newrole"}}
	ctrl.unsupportedByMount["auth/legacy/"] = true

	resp, err := backend.handleIntrospectRoles(ctx, jwtRequest(t), nil)
	require.NoError(t, err)

	roles := resp.Data["roles"].([]aggregatedRole)
	require.Len(t, roles, 1)
	assert.Equal(t, "newrole", roles[0].Name)
	assert.Equal(t, "modern/", roles[0].AuthPath)

	// The legacy mount was silently skipped — no warning.
	warnings := resp.Data["warnings"].([]string)
	assert.Empty(t, warnings, "mounts returning ErrUnsupportedPath should be silent, not warn")
}

// Namespace scoping: an agent calling from namespace B must not see roles
// from mounts in namespace A. We mount in the root namespace (used by
// setupTestSystemBackend), then call the handler with a context carrying
// a different namespace — the filter excludes all mounts.
func TestSystemBackend_Introspect_NamespaceScoping(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()

	core.authMethods["jwt"] = ctrl.factory()
	require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: "root-mount/"}))
	ctrl.rolesByMount["auth/root-mount/"] = []map[string]any{{"name": "root-role"}}

	// Sanity: from the root namespace, the role is visible.
	resp, err := backend.handleIntrospectRoles(ctx, jwtRequest(t), nil)
	require.NoError(t, err)
	roles := resp.Data["roles"].([]aggregatedRole)
	require.Len(t, roles, 1)

	// Now call from a different, synthetic namespace — the aggregator
	// must return empty because the mount's NamespaceID does not match.
	otherNS := &namespace.Namespace{ID: "nsOther", Path: "nsOther/"}
	otherCtx := namespace.ContextWithNamespace(context.Background(), otherNS)
	resp, err = backend.handleIntrospectRoles(otherCtx, jwtRequest(t), nil)
	require.NoError(t, err)
	roles = resp.Data["roles"].([]aggregatedRole)
	assert.Empty(t, roles, "roles from another namespace must not leak")
}

// Fan-out must run mount calls in parallel, not serially. With 5 mounts
// each sleeping 80ms, serial execution would take ≥400ms; parallel
// execution should finish close to the single-mount latency.
func TestSystemBackend_Introspect_FanOutRunsInParallel(t *testing.T) {
	backend, ctx, core := setupTestSystemBackend(t)
	ctrl := newIntrospectMock()

	core.authMethods["jwt"] = ctrl.factory()

	const nMounts = 5
	const perMountDelay = 80 * time.Millisecond
	for i := 0; i < nMounts; i++ {
		path := fmt.Sprintf("p%d/", i)
		require.NoError(t, core.mount(ctx, &MountEntry{Class: mountClassAuth, Type: "jwt", Path: path}))
		ctrl.delayByMount["auth/"+path] = perMountDelay
		ctrl.rolesByMount["auth/"+path] = []map[string]any{{"name": fmt.Sprintf("r%d", i)}}
	}

	start := time.Now()
	resp, err := backend.handleIntrospectRoles(ctx, jwtRequest(t), nil)
	elapsed := time.Since(start)
	require.NoError(t, err)

	roles := resp.Data["roles"].([]aggregatedRole)
	require.Len(t, roles, nMounts)

	// Allow generous headroom for scheduler noise and test machine load
	// (slow CI). The guard is against regressing to sequential execution,
	// not a strict p99 budget — sequential would be ≥400ms.
	const maxAllowed = 250 * time.Millisecond
	assert.Less(t, elapsed, maxAllowed,
		"fan-out should run in parallel (%d mounts × %v); got %v", nMounts, perMountDelay, elapsed)
}
