package jwt

import (
	"testing"

	"github.com/stephnangue/warden/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorizationServerURL covers what this mount will advertise to clients
// through RFC 9728 protected resource metadata. The value sends a user's browser
// somewhere to authenticate, so naming the wrong place — or naming anywhere at
// all when the mount does not actually know an issuer — is worse than staying
// silent and letting the metadata endpoint 404.
func TestAuthorizationServerURL(t *testing.T) {
	newBackend := func(t *testing.T, cfg *JWTAuthConfig) *jwtAuthBackend {
		t.Helper()
		b := &jwtAuthBackend{logger: testLogger(), config: cfg}
		return b
	}

	t.Run("discovery URL is the issuer", func(t *testing.T) {
		b := newBackend(t, &JWTAuthConfig{OIDCDiscoveryURL: "https://idp.example.com"})
		got, ok := b.AuthorizationServerURL()
		assert.True(t, ok)
		assert.Equal(t, "https://idp.example.com", got)
	})

	t.Run("discovery URL wins over bound_issuer", func(t *testing.T) {
		b := newBackend(t, &JWTAuthConfig{
			OIDCDiscoveryURL: "https://idp.example.com",
			BoundIssuer:      "https://other.example.com",
		})
		got, _ := b.AuthorizationServerURL()
		assert.Equal(t, "https://idp.example.com", got,
			"discovery is by construction somewhere a client can run discovery against")
	})

	t.Run("bound_issuer is used when it is an absolute https URL", func(t *testing.T) {
		b := newBackend(t, &JWTAuthConfig{BoundIssuer: "https://issuer.example.com"})
		got, ok := b.AuthorizationServerURL()
		assert.True(t, ok)
		assert.Equal(t, "https://issuer.example.com", got)
	})

	t.Run("a non-URL bound_issuer names nothing", func(t *testing.T) {
		// bound_issuer is free-form and often an opaque identifier rather than a
		// location. Publishing one as somewhere to send credentials would be
		// meaningless at best.
		for _, issuer := range []string{
			"my-issuer",
			"urn:example:issuer",
			"http://idp.example.com",
			"//idp.example.com",
			"https://",
		} {
			b := newBackend(t, &JWTAuthConfig{BoundIssuer: issuer})
			_, ok := b.AuthorizationServerURL()
			assert.False(t, ok, "bound_issuer %q must not be advertised", issuer)
		}
	})

	t.Run("a JWKS-only or static-key mount names nothing", func(t *testing.T) {
		// These verify tokens without knowing who issues them. There is nothing
		// for a client to discover, and guessing would send a user to the wrong
		// authorization server.
		for name, cfg := range map[string]*JWTAuthConfig{
			"jwks only":   {JWKSURL: "https://idp.example.com/keys"},
			"static keys": {JWTValidationPubKeys: []string{"-----BEGIN PUBLIC KEY-----"}},
			"empty":       {},
		} {
			t.Run(name, func(t *testing.T) {
				_, ok := newBackend(t, cfg).AuthorizationServerURL()
				assert.False(t, ok)
			})
		}
	})

	t.Run("an unconfigured backend names nothing", func(t *testing.T) {
		_, ok := newBackend(t, nil).AuthorizationServerURL()
		assert.False(t, ok, "a nil config must not panic")
	})

	t.Run("satisfies the interface the metadata endpoint reaches it through", func(t *testing.T) {
		// The concrete type is unexported, so core can only reach this via the
		// interface. If the assertion ever breaks, metadata silently 404s.
		var b any = newBackend(t, &JWTAuthConfig{OIDCDiscoveryURL: "https://idp.example.com"})
		provider, ok := b.(logical.AuthorizationServerProvider)
		require.True(t, ok)
		got, ok := provider.AuthorizationServerURL()
		assert.True(t, ok)
		assert.Equal(t, "https://idp.example.com", got)
	})
}
