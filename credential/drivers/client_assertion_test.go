package drivers

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientAssertionClaims: the claims bind the assertion to one client and one
// server, live briefly, and are never alike — a server that enforces single use (OIDC
// Core, Okta, Keycloak) refuses a repeated jti.
func TestClientAssertionClaims(t *testing.T) {
	a, err := clientAssertionClaims("client-1", "https://as.example/token")
	require.NoError(t, err)
	b, err := clientAssertionClaims("client-1", "https://as.example/token")
	require.NoError(t, err)

	assert.Equal(t, "client-1", a["iss"])
	assert.Equal(t, "client-1", a["sub"])
	assert.Equal(t, "https://as.example/token", a["aud"])
	assert.NotEmpty(t, a["jti"])
	assert.NotEqual(t, a["jti"], b["jti"], "every assertion carries its own jti")

	iat, exp := a["iat"].(int64), a["exp"].(int64)
	assert.Equal(t, int64(clientAssertionTTL/time.Second), exp-iat)
}

// TestBasicClientAuthHeader: RFC 6749 §2.3.1 form-urlencodes the id and the secret
// before Basic-encoding them, so a ':' in either cannot be mistaken for the separator.
func TestBasicClientAuthHeader(t *testing.T) {
	header := basicClientAuthHeader("id:with colon", "s3cr%t:")
	require.True(t, strings.HasPrefix(header, "Basic "))
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
	require.NoError(t, err)
	assert.Equal(t, "id%3Awith+colon:s3cr%25t%3A", string(raw))
}

// TestChainedClientAuthFromMaterial: which key names are read depends on the method,
// and everything a payload lacks is reported as incomplete so a stale cached payload is
// refetched; a method chaining cannot serve is a config error and is not.
func TestChainedClientAuthFromMaterial(t *testing.T) {
	cases := []struct {
		name       string
		clientAuth string
		material   credential.SecretMaterial
		wantSecret string
		wantKid    string
		errMsg     string
		incomplete bool
	}{
		{
			name:       "client secret by convention",
			clientAuth: clientAuthSecretPost,
			material:   credential.SecretMaterial{Data: map[string]string{"client_id": "c", "client_secret": "s"}},
			wantSecret: "s",
		},
		{
			name:       "basic reads the same payload as post",
			clientAuth: clientAuthSecretBasic,
			material:   credential.SecretMaterial{Data: map[string]string{"client_id": "c", "client_secret": "s"}},
			wantSecret: "s",
		},
		{
			name:       "private key with kid",
			clientAuth: clientAuthPrivateKeyJWT,
			material:   credential.SecretMaterial{Data: map[string]string{"client_id": "c", "private_key": "PEM", "client_assertion_kid": "k1"}},
			wantSecret: "PEM",
			wantKid:    "k1",
		},
		{
			name:       "private key with the short kid name",
			clientAuth: clientAuthPrivateKeyJWT,
			material:   credential.SecretMaterial{Data: map[string]string{"client_id": "c", "private_key": "PEM", "kid": "k2"}},
			wantSecret: "PEM",
			wantKid:    "k2",
		},
		{
			name:       "the id is never the secret",
			clientAuth: clientAuthSecretPost,
			material:   credential.SecretMaterial{Data: map[string]string{"client_id": "c"}, Field: "client_id"},
			errMsg:     "holds a client id but no secret",
			incomplete: true,
		},
		{
			name:       "named field missing",
			clientAuth: clientAuthPrivateKeyJWT,
			material:   credential.SecretMaterial{Data: map[string]string{"client_id": "c", "other": "x"}, Field: "pem"},
			errMsg:     `secret_field "pem" is empty or absent`,
			incomplete: true,
		},
		{
			name:       "no private key",
			clientAuth: clientAuthPrivateKeyJWT,
			material:   credential.SecretMaterial{Data: map[string]string{"client_id": "c", "a": "1", "b": "2"}},
			errMsg:     "no private key in fetched secret material",
			incomplete: true,
		},
		{
			name:       "no client id",
			clientAuth: clientAuthSecretPost,
			material:   credential.SecretMaterial{Data: map[string]string{"client_secret": "s", "other": "x"}},
			errMsg:     "no client id in fetched secret material",
			incomplete: true,
		},
		{
			name:       "a method chaining cannot serve",
			clientAuth: clientAuthNone,
			material:   credential.SecretMaterial{Data: map[string]string{"client_id": "c", "client_secret": "s"}},
			errMsg:     "credential chaining supports client_auth",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := chainedClientAuthFromMaterial(tc.clientAuth, tc.material)
			if tc.errMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
				assert.False(t, strings.HasPrefix(err.Error(), "token_exchange"), "shared errors leave naming the driver to the driver")
				if tc.incomplete {
					assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
				} else {
					assert.NotErrorIs(t, err, credential.ErrChainedSecretIncomplete)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "c", auth.clientID)
			assert.Equal(t, tc.wantSecret, auth.secret)
			assert.Equal(t, tc.wantKid, auth.kid)
			assert.Nil(t, auth.kms)
		})
	}
}
