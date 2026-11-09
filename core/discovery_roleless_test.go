// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package core

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// introspectEntry returns the request audit entry of sys/introspect/roles.
func introspectEntry(t *testing.T, rec *auditCapture) *audit.LogEntry {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, e := range rec.requests {
		if e.Request != nil && e.Request.Path == "sys/introspect/roles" {
			return e
		}
	}
	t.Fatalf("no request audit entry for sys/introspect/roles among %d", len(rec.requests))
	return nil
}

// A role-less request runs as the identity token the gateway would hold for
// the same credential at the same mount, under the built-ins alone, and its
// audit entry says how it was admitted, never which groups matched.
func TestRoleless_IntrospectAuditedAsIdentity(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))
	rec := &auditCapture{}
	e.c.auditManager = rec

	assert.Equal(t, []string{"deploy"}, roleNames(e.introspectRoles()))
	assert.Equal(t, int64(1), m.admits.Load(), "the leg and the handler share one admission")

	accessor := e.c.router.MatchingMountEntry(e.ctx, "auth/jwt/").Accessor
	wantID := identityTokenType.ComputeID(identityTokenType.LookupValue("eyJ.any.token", accessor))

	entry := introspectEntry(t, rec)
	require.NotNil(t, entry.Auth)
	assert.Equal(t, TypeIdentityToken, entry.Auth.TokenType)
	assert.Equal(t, wantID, entry.Auth.TokenID, "the gateway's identity token ID for this credential")
	assert.Equal(t, "agent-1", entry.Auth.PrincipalID)
	assert.Equal(t, []string{builtinCBPPolicy, builtinMCPPolicy, builtinSponsorPolicy}, entry.Auth.Policies)
	require.NotNil(t, entry.Auth.Discovery)
	assert.Equal(t, []audit.AdmittedMount{{Mount: "jwt/", PrincipalID: "agent-1"}}, entry.Auth.Discovery.AdmittedBy)
	assert.Equal(t, 1, entry.Auth.Discovery.RolesGranted)
	assert.False(t, entry.Auth.Discovery.Anonymous)

	raw, err := json.Marshal(entry)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "deployers", "no group is named")
	assert.Empty(t, entry.Auth.Groups)
	assert.Empty(t, entry.Auth.RoleName)
}

// A role selection on an identity path is ignored: the request takes no role.
func TestRoleless_RoleSelectionIgnored(t *testing.T) {
	e := newDiscEnv(t, "", "")
	e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))

	req := bearerRequest("eyJ.any.token")
	req.HTTPRequest.Header.Set("X-Warden-Role", "ghost")
	resp, err := e.introspectAs(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NoError(t, resp.Err)
	assert.Equal(t, []string{"deploy"}, roleNames(resp.Data["roles"].([]admittedRole)))
}

// A namespace with no roles still admits a valid credential, through its own
// auto_auth_path, and grants it nothing.
func TestRoleless_NamespaceWithoutRoles(t *testing.T) {
	e := newDiscEnv(t, "team/", "auth/jwt/")
	m := e.mountAuth("jwt/")

	assert.Empty(t, e.introspectRoles())
	assert.Equal(t, int64(1), m.admits.Load())

	m.claims = nil
	e.assertIntrospectUnauthorized(errRolelessNotAdmitted)
}

// No credential at all is refused before any admission.
func TestRoleless_NoCredential(t *testing.T) {
	e := newDiscEnv(t, "", "")
	m := e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")

	resp, err := e.introspectAs(bearerRequest(""))
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, rolelessChallenge, resp.Headers.Get("WWW-Authenticate"))
	assert.Zero(t, m.admits.Load())
}

// The built-in policies are what authorize a role-less request: withdrawing
// their grant on the path refuses it.
func TestRoleless_GatedByBuiltins(t *testing.T) {
	e := newDiscEnv(t, "", "")
	e.mountAuth("jwt/")
	e.provider("vault", "vault/", "auth/jwt/")
	e.role("deploy", "vault/", "")
	e.group("deployers", []string{"deploy"}, time.Time{}, discRule([]string{"auth/jwt/"}, "acme/*"))

	p := testParsePolicy(t, `path "sys/mcp" { capabilities = ["create", "read", "delete"] }`)
	p.Name, p.Type = builtinCBPPolicy, PolicyTypeCBP
	require.NoError(t, e.c.policyStore.SetPolicy(rootCtx(), p, nil))

	resp, err := e.introspectAs(bearerRequest("eyJ.any.token"))
	require.Error(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// sys/introspect/roles is an identity path; only the system backend may
// declare one, and never as a root or an unauthenticated path too.
func TestIdentityPaths_Declaration(t *testing.T) {
	c := createTestCore(t)
	ctx := namespace.ContextWithNamespace(context.Background(), namespace.RootNamespace)
	assert.True(t, c.router.IdentityPath(ctx, "sys/introspect/roles"))
	assert.False(t, c.router.IdentityPath(ctx, "sys/introspect"))
	assert.False(t, c.router.IdentityPath(ctx, "sys/roles"))

	auth := &framework.Backend{BackendClass: logical.ClassAuth}
	assert.Error(t, validateIdentityPaths(auth, &logical.Paths{Identity: []string{"x"}}))

	sys := &framework.Backend{BackendClass: logical.ClassSystem}
	assert.NoError(t, validateIdentityPaths(sys, &logical.Paths{Identity: []string{"x"}}))
	assert.Error(t, validateIdentityPaths(sys, &logical.Paths{Identity: []string{"x"}, Root: []string{"x"}}))
	assert.Error(t, validateIdentityPaths(sys, &logical.Paths{Identity: []string{"x"}, Unauthenticated: []string{"x"}}))
	assert.NoError(t, validateIdentityPaths(auth, &logical.Paths{}), "no identity path, nothing to refuse")
}
