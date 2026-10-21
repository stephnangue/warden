package cert

import (
	"context"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/auth/helper/factstest"
	"github.com/stephnangue/warden/logical"
)

// admitRequest routes introspect/admit to b with cert forwarded, marked
// internal as core marks it when internal is set.
func admitRequest(t *testing.T, b *certAuthBackend, cert *x509.Certificate, internal bool) *logical.Response {
	t.Helper()
	req := &logical.Request{Operation: logical.ReadOperation, Path: helper.AdmitPattern, Internal: internal}
	if cert != nil {
		req.HTTPRequest = newCertHTTPRequest(t, cert)
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

func admitted(t *testing.T, resp *logical.Response) *logical.Admission {
	t.Helper()
	require.NoError(t, resp.Err)
	ok, _ := resp.Data[helper.AdmittedKey].(bool)
	adm, _ := resp.Data[helper.AdmissionKey].(*logical.Admission)
	assert.Equal(t, ok, adm != nil)
	return adm
}

func agentLeaf(t *testing.T, ca *authority, mutate func(*x509.Certificate)) *x509.Certificate {
	return issueLeaf(t, ca, newFixtureKey(t), func(c *x509.Certificate) {
		c.Subject.CommonName = "agent-1"
		if mutate != nil {
			mutate(c)
		}
	})
}

func TestAdmit_RefusedUnlessInternal(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	b := factsBackend(t, root, nil)
	resp := admitRequest(t, b, agentLeaf(t, root, nil), false)
	require.Error(t, resp.Err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.NotContains(t, resp.Data, helper.AdmissionKey)
	assert.NotContains(t, b.PathsSpecial.Unauthenticated, helper.AdmitPattern)
}

func TestAdmit_Valid(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	b := factsBackend(t, root, map[string]any{"facts": map[string]any{"cn": "workload"}})
	// Admission ignores roles: reader admits agent-* only, this is server-1.
	leaf := agentLeaf(t, root, func(c *x509.Certificate) { c.Subject.CommonName = "server-1" })

	adm := admitted(t, admitRequest(t, b, leaf, true))
	require.NotNil(t, adm)
	assert.Same(t, b.mountFacts, adm.Mount)
	assert.Empty(t, adm.MountPath)
	assert.True(t, adm.IssuedAt.IsZero())
	n := adm.Mount.Load()
	assert.Equal(t, []string{"server-1"}, factstest.Values(adm, n, "workload"))
	assert.Equal(t, []string{fingerprint(root.cert)}, factstest.Values(adm, n, "ca"))
}

func TestAdmit_NotAdmitted(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	untrusted := issueCA(t, "Untrusted", newFixtureKey(t), nil)
	b := factsBackend(t, root, nil)
	// A role CA is not the mount's: a certificate only it issues is not admitted.
	require.NoError(t, b.setRole(context.Background(), &CertRole{
		Name: "pinned", Certificate: untrusted.pem, TokenPolicies: []string{"p"}, TokenTTL: "1h", TokenType: "cert_role",
	}))

	cases := map[string]*x509.Certificate{
		"no certificate":      nil,
		"untrusted CA":        agentLeaf(t, untrusted, nil),
		"server auth only":    agentLeaf(t, root, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }),
		"no principal (cn)":   agentLeaf(t, root, func(c *x509.Certificate) { c.Subject.CommonName = "" }),
		"self-signed unknown": issueCA(t, "agent-1", newFixtureKey(t), nil).cert,
	}
	for name, cert := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, admitted(t, admitRequest(t, b, cert, true)))
		})
	}
}

// A mount without a trusted CA cannot decide: an error, which discovery reports
// as the mount's warning. Without a certificate there is nothing to decide.
func TestAdmit_NoTrustedCA(t *testing.T) {
	b, _ := createTestBackend(t)
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: helper.AdmitPattern, Internal: true,
		HTTPRequest: newCertHTTPRequest(t, agentLeaf(t, root, nil)),
	})
	assert.ErrorIs(t, err, errNoTrustedCA)
	assert.ErrorIs(t, err, helper.ErrAdmitNoTrustedCA, "discovery reports the class")
	assert.Nil(t, resp)
	assert.Nil(t, admitted(t, admitRequest(t, b, nil, true)))
}

// The mount's principal_claim decides which field must be present.
func TestAdmit_PrincipalClaim(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	b := factsBackend(t, root, map[string]any{"principal_claim": "dns_san"})
	assert.Nil(t, admitted(t, admitRequest(t, b, agentLeaf(t, root, nil), true)))
	assert.NotNil(t, admitted(t, admitRequest(t, b, agentLeaf(t, root, func(c *x509.Certificate) {
		c.DNSNames = []string{"a.example.com"}
	}), true)))
}

// Revocation is not checked at admission, as discovery never checked it: a
// certificate a strict CRL check refuses at login is still admitted.
func TestAdmit_RevocationSkipped(t *testing.T) {
	root := issueCA(t, "Root", newFixtureKey(t), nil)
	b := factsBackend(t, root, map[string]any{"revocation_mode": "crl"})
	leaf := agentLeaf(t, root, nil) // no CRL distribution point: the CRL check fails

	resp := certLogin(t, b, leaf)
	require.Error(t, resp.Err, "login checks revocation")
	assert.NotNil(t, admitted(t, admitRequest(t, b, leaf, true)))
}
