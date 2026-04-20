// Copyright (c) 2024 Warden Project
// SPDX-License-Identifier: MPL-2.0

package cert

import (
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

func TestPathIntrospect_Structure(t *testing.T) {
	b, _ := createTestBackend(t)
	p := b.pathIntrospect()

	assert.Equal(t, "introspect/roles", p.Pattern)
	_, hasRead := p.Operations[logical.ReadOperation]
	assert.True(t, hasRead)
}

func TestHandleIntrospect_NoCert(t *testing.T) {
	// No client cert in the request context.
	b, ctx := createTestBackend(t)
	b.config = &CertAuthConfig{PrincipalClaim: "cn"}

	resp, err := b.handleIntrospectRoles(ctx, &logical.Request{}, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles)
}

func TestHandleIntrospect_FiltersByCertConstraints(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	cert := testClientCert(t, caCert, caKey, "agent-prod", func(tmpl *x509.Certificate) {
		tmpl.DNSNames = []string{"agent-prod.example.com"}
	})

	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{
		"trusted_ca_pem":  caPEM,
		"principal_claim": "cn",
	}))

	// matches
	require.NoError(t, b.setRole(ctx, &CertRole{
		Name:               "prod-reader",
		Description:        "read-only prod",
		AllowedCommonNames: []string{"agent-prod"},
		TokenTTL:           "1h",
	}))
	// does not match — CN constraint is different
	require.NoError(t, b.setRole(ctx, &CertRole{
		Name:               "staging-reader",
		Description:        "read-only staging",
		AllowedCommonNames: []string{"agent-staging"},
		TokenTTL:           "1h",
	}))

	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, cert)}
	resp, err := b.handleIntrospectRoles(ctx, req, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	roles := resp.Data["roles"].([]introspectedRole)
	require.Len(t, roles, 1)
	assert.Equal(t, "prod-reader", roles[0].Name)
	assert.Equal(t, "read-only prod", roles[0].Description)
}

func TestHandleIntrospect_RejectsCertFromUnknownCA(t *testing.T) {
	// Cert signed by CA A; backend trusts CA B.
	caA, caAKey, _ := testCA(t)
	_, _, caBPEM := testCA(t)

	cert := testClientCert(t, caA, caAKey, "agent-prod")

	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{
		"trusted_ca_pem":  caBPEM, // different CA
		"principal_claim": "cn",
	}))
	require.NoError(t, b.setRole(ctx, &CertRole{
		Name:               "role1",
		AllowedCommonNames: []string{"agent-*"},
		TokenTTL:           "1h",
	}))

	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, cert)}
	resp, err := b.handleIntrospectRoles(ctx, req, nil)
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles, "cert signed by untrusted CA should match no roles")
}

func TestHandleIntrospect_EmptyWhenNoRoles(t *testing.T) {
	caCert, caKey, caPEM := testCA(t)
	cert := testClientCert(t, caCert, caKey, "agent")

	b, ctx := createTestBackend(t)
	require.NoError(t, b.setupCertConfig(ctx, map[string]any{
		"trusted_ca_pem":  caPEM,
		"principal_claim": "cn",
	}))

	req := &logical.Request{HTTPRequest: newCertHTTPRequest(t, cert)}
	resp, err := b.handleIntrospectRoles(ctx, req, nil)
	require.NoError(t, err)
	roles := resp.Data["roles"].([]introspectedRole)
	assert.Empty(t, roles)
}
