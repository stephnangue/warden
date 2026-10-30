package oidc

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stephnangue/warden/logical"
)

func TestValidate_Defaults(t *testing.T) {
	c := &oidcConfig{}
	_ = c.validate()
	assert.Equal(t, []string{"RS256"}, c.SupportedAlgs)
	assert.Equal(t, []string{"openid", "profile"}, c.Scopes)
	assert.Equal(t, time.Hour, c.SessionTTL)
	assert.Equal(t, clientAuthSecret, c.ClientAuth)
	assert.Equal(t, logical.EntityKindHuman, c.EntityKind)
}

func TestRedirectAllowed(t *testing.T) {
	allowed := []string{"http://127.0.0.1/oidc/callback", "http://[::1]/oidc/callback", "http://localhost/cb", "https://warden.example/cb"}
	for uri, want := range map[string]bool{
		"http://127.0.0.1:53412/oidc/callback":  true,
		"http://127.0.0.1/oidc/callback":        true,
		"http://[::1]:8080/oidc/callback":       true,
		"http://localhost:9999/cb":              true,
		"https://warden.example/cb":             true,
		"https://warden.example:8443/cb":        false,
		"http://127.0.0.1:53412/other":          false,
		"https://127.0.0.1:53412/oidc/callback": false,
		"http://127.0.0.2:53412/oidc/callback":  false,
		// Other spellings of a loopback address are not the literals cap
		// accepts on any port, so neither does the mount.
		"http://[0:0:0:0:0:0:0:1]:8080/oidc/callback":  false,
		"http://[::ffff:127.0.0.1]:8080/oidc/callback": false,
	} {
		assert.Equal(t, want, redirectAllowed(allowed, uri), uri)
	}
}

func TestCertificateThumbprint(t *testing.T) {
	key, _, certPEM := rsaKey(t)
	thumb, err := certificateThumbprint(certPEM, key)
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	sum := sha256.Sum256(cert.Raw)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), thumb)

	other, _, _ := rsaKey(t)
	_, err = certificateThumbprint(certPEM, other)
	assert.ErrorContains(t, err, "does not certify private_key")
	_, err = certificateThumbprint("x", key)
	assert.ErrorContains(t, err, "not PEM")
}

func TestExtraScopes(t *testing.T) {
	c := &oidcConfig{Scopes: []string{"openid", "profile", "email"}}
	assert.Equal(t, []string{"profile", "email"}, c.extraScopes(), "cap adds openid itself")
}
