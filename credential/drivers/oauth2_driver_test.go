package drivers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mintTestJWT builds an unsigned-shape JWT (header.payload.sig) carrying the
// given JSON claims, for exercising the local JWT-decode metadata path.
func mintTestJWT(payloadJSON string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc([]byte(payloadJSON)) + "." + enc([]byte("sig"))
}

// =============================================================================
// Factory Tests
// =============================================================================

func TestOAuth2DriverFactory_Type(t *testing.T) {
	f := &OAuth2DriverFactory{}
	assert.Equal(t, credential.SourceTypeOAuth2, f.Type())
}

func TestOAuth2DriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &OAuth2DriverFactory{}
	fields := f.SensitiveConfigFields()
	assert.Contains(t, fields, "client_secret")
	assert.Contains(t, fields, "ca_data")
	assert.Len(t, fields, 2)
}

func TestOAuth2DriverFactory_InferCredentialType(t *testing.T) {
	f := &OAuth2DriverFactory{}
	ct, err := f.InferCredentialType(map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeOAuthBearerToken, ct)
}

func TestOAuth2DriverFactory_ValidateConfig(t *testing.T) {
	f := &OAuth2DriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     "https://auth.example.com/oauth/token",
			},
			wantErr: false,
		},
		{
			name: "valid config with all optional fields",
			config: map[string]string{
				"client_id":        "test-client-id",
				"client_secret":    "test-client-secret",
				"token_url":        "https://auth.example.com/oauth/token",
				"default_scopes":   "read write",
				"verify_url":       "https://api.example.com/me",
				"verify_method":    "GET",
				"auth_header_type": "bearer",
				"display_name":     "MyProvider",
			},
			wantErr: false,
		},
		{
			// client_id/client_secret are optional at the source level: the
			// authorization_code flow keeps them on the spec, and presence is
			// checked at mint time.
			name: "client_id optional at source level",
			config: map[string]string{
				"client_secret": "test-client-secret",
				"token_url":     "https://auth.example.com/oauth/token",
			},
			wantErr: false,
		},
		{
			name: "client_secret optional at source level",
			config: map[string]string{
				"client_id": "test-client-id",
				"token_url": "https://auth.example.com/oauth/token",
			},
			wantErr: false,
		},
		{
			name: "source with only token_url (creds on spec)",
			config: map[string]string{
				"token_url": "https://auth.example.com/oauth/token",
			},
			wantErr: false,
		},
		{
			name: "valid auth_url for authorization_code",
			config: map[string]string{
				"token_url": "https://github.com/login/oauth/access_token",
				"auth_url":  "https://github.com/login/oauth/authorize",
			},
			wantErr: false,
		},
		{
			name: "auth_url SSRF-blocked (metadata address)",
			config: map[string]string{
				"token_url": "https://auth.example.com/oauth/token",
				"auth_url":  "https://169.254.169.254/latest/meta-data/",
			},
			wantErr: true,
			errMsg:  "must not target a loopback/private/link-local address",
		},
		{
			// token_url is server-fetched (the client secret is POSTed there),
			// so it must be SSRF-guarded too.
			name: "token_url SSRF-blocked (private address)",
			config: map[string]string{
				"token_url": "https://10.0.0.5/oauth/token",
			},
			wantErr: true,
			errMsg:  "must not target a loopback/private/link-local address",
		},
		{
			name: "missing token_url",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
			},
			wantErr: true,
			errMsg:  "token_url",
		},
		{
			name:    "missing all required",
			config:  map[string]string{},
			wantErr: true,
		},
		{
			name: "invalid token_url - http scheme",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     "http://example.com/token",
			},
			wantErr: true,
			errMsg:  "must use https://",
		},
		{
			name: "invalid token_url - no host",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     "https://",
			},
			wantErr: true,
			errMsg:  "must include a host",
		},
		{
			name: "invalid verify_url - http scheme",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     "https://auth.example.com/token",
				"verify_url":    "http://api.example.com/me",
			},
			wantErr: true,
			errMsg:  "must use https://",
		},
		{
			name: "invalid verify_method",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     "https://auth.example.com/token",
				"verify_method": "DELETE",
			},
			wantErr: true,
			errMsg:  "verify_method must be GET or POST",
		},
		{
			name: "invalid auth_header_type",
			config: map[string]string{
				"client_id":        "test-client-id",
				"client_secret":    "test-client-secret",
				"token_url":        "https://auth.example.com/token",
				"auth_header_type": "basic",
			},
			wantErr: true,
			errMsg:  "auth_header_type must be one of",
		},
		{
			name: "custom_header without auth_header_name",
			config: map[string]string{
				"client_id":        "test-client-id",
				"client_secret":    "test-client-secret",
				"token_url":        "https://auth.example.com/token",
				"auth_header_type": "custom_header",
			},
			wantErr: true,
			errMsg:  "auth_header_name is required",
		},
		{
			name: "custom_header with auth_header_name",
			config: map[string]string{
				"client_id":        "test-client-id",
				"client_secret":    "test-client-secret",
				"token_url":        "https://auth.example.com/token",
				"auth_header_type": "custom_header",
				"auth_header_name": "X-Api-Key",
			},
			wantErr: false,
		},
		{
			name: "valid config with token_param extra params",
			config: map[string]string{
				"client_id":            "test-client-id",
				"client_secret":        "test-client-secret",
				"token_url":            "https://auth.example.com/token",
				"token_param.resource": "urn:dtaccount:abc123",
				"token_param.audience": "https://api.example.com",
			},
			wantErr: false,
		},
		{
			name: "token_param overriding grant_type",
			config: map[string]string{
				"client_id":              "test-client-id",
				"client_secret":          "test-client-secret",
				"token_url":              "https://auth.example.com/token",
				"token_param.grant_type": "password",
			},
			wantErr: true,
			errMsg:  "token_param.grant_type cannot override core OAuth2 field",
		},
		{
			name: "token_param overriding client_id",
			config: map[string]string{
				"client_id":             "test-client-id",
				"client_secret":         "test-client-secret",
				"token_url":             "https://auth.example.com/token",
				"token_param.client_id": "override",
			},
			wantErr: true,
			errMsg:  "token_param.client_id cannot override core OAuth2 field",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := f.ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOAuth2DriverFactory_Create(t *testing.T) {
	f := &OAuth2DriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := f.Create(map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
		"token_url":     "https://auth.example.com/token",
	}, log)
	require.NoError(t, err)
	require.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeOAuth2, driver.Type())
}

// =============================================================================
// Driver Tests
// =============================================================================

func createTestOAuth2Driver(t *testing.T, config map[string]string) *OAuth2Driver {
	t.Helper()
	f := &OAuth2DriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := f.Create(config, log)
	require.NoError(t, err)
	return driver.(*OAuth2Driver)
}

func TestOAuth2Driver_Type(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
		"token_url":     "https://auth.example.com/token",
	})
	assert.Equal(t, credential.SourceTypeOAuth2, d.Type())
}

func TestOAuth2Driver_Cleanup(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
		"token_url":     "https://auth.example.com/token",
	})
	assert.NoError(t, d.Cleanup(context.Background()))
}

func TestOAuth2Driver_Revoke_NoOp(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
		"token_url":     "https://auth.example.com/token",
	})
	assert.NoError(t, d.Revoke(context.Background(), "any-lease-id"))
	assert.NoError(t, d.Revoke(context.Background(), ""))
}

func TestOAuth2Driver_NotRotatable(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
		"token_url":     "https://auth.example.com/token",
	})
	var sd credential.SourceDriver = d
	_, ok := sd.(credential.Rotatable)
	assert.False(t, ok, "OAuth2Driver should not implement credential.Rotatable")
}

func TestOAuth2Driver_MintCredential(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		assert.Equal(t, "test-client-id", r.Form.Get("client_id"))
		assert.Equal(t, "test-client-secret", r.Form.Get("client_secret"))
		assert.Equal(t, "read write", r.Form.Get("scope"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "eyJ-test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read write",
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     server.URL,
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test",
		Type:   credential.TypeOAuthBearerToken,
		Config: map[string]string{"scope": "read write"},
	}

	rawData, _, ttl, leaseID, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "eyJ-test-access-token", rawData["api_key"])
	assert.Equal(t, "Bearer", rawData["token_type"])
	assert.Equal(t, "read write", rawData["scope"])
	assert.Equal(t, 3600*time.Second, ttl)
	assert.Empty(t, leaseID)
}

func TestOAuth2Driver_MintCredential_DefaultScope(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)
		assert.Equal(t, "default-scope", r.Form.Get("scope"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   1800,
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":      "test-id",
				"client_secret":  "test-secret",
				"token_url":      server.URL,
				"default_scopes": "default-scope",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test",
		Type:   credential.TypeOAuthBearerToken,
		Config: map[string]string{},
	}

	rawData, _, ttl, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "test-token", rawData["api_key"])
	assert.Equal(t, 1800*time.Second, ttl)
}

func TestOAuth2Driver_MintCredential_ExtraTokenParams(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		// Core fields still present
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		assert.Equal(t, "test-id", r.Form.Get("client_id"))

		// Extra token params
		assert.Equal(t, "urn:dtaccount:abc123", r.Form.Get("resource"))
		assert.Equal(t, "https://api.example.com", r.Form.Get("audience"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":            "test-id",
				"client_secret":        "test-secret",
				"token_url":            server.URL,
				"token_param.resource": "urn:dtaccount:abc123",
				"token_param.audience": "https://api.example.com",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test",
		Type:   credential.TypeOAuthBearerToken,
		Config: map[string]string{},
	}

	rawData, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "test-token", rawData["api_key"])
}

func TestOAuth2Driver_MintCredential_NoExpiresIn(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":     "test-id",
				"client_secret": "test-secret",
				"token_url":     server.URL,
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{},
	}

	_, _, ttl, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), ttl)
}

func TestOAuth2Driver_MintCredential_MissingCredentials(t *testing.T) {
	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOAuth2,
			Config: map[string]string{},
		},
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing client_id or client_secret")
}

func TestOAuth2Driver_MintCredential_TokenEndpointError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer server.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":     "bad-id",
				"client_secret": "bad-secret",
				"token_url":     server.URL,
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange failed")
}

func TestOAuth2Driver_MintCredential_EmptyAccessToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "",
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":     "test-id",
				"client_secret": "test-secret",
				"token_url":     server.URL,
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing access_token")
}

func TestOAuth2Driver_MintCredential_MalformedJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`not-json`))
	}))
	defer server.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":     "test-id",
				"client_secret": "test-secret",
				"token_url":     server.URL,
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode")
}

func TestOAuth2Driver_MintCredential_DisplayName(t *testing.T) {
	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"display_name": "PagerDuty",
			},
		},
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PagerDuty OAuth2 source missing")
}

// =============================================================================
// VerifySpec Tests
// =============================================================================

func TestOAuth2Driver_VerifySpec(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "verify-test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	verifyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "Bearer verify-test-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user":{"id":"PUSER123"}}`))
	}))
	defer verifyServer.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":     "test-id",
				"client_secret": "test-secret",
				"token_url":     tokenServer.URL,
				"verify_url":    verifyServer.URL,
				"verify_method": "GET",
			},
		},
		httpClient: tokenServer.Client(),
	}
	// Use the same TLS client for both servers
	d.httpClient.Transport = tokenServer.Client().Transport

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	err := d.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestOAuth2Driver_VerifySpec_NoVerifyURL(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":     "test-id",
				"client_secret": "test-secret",
				"token_url":     tokenServer.URL,
			},
		},
		httpClient: tokenServer.Client(),
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	err := d.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestOAuth2Driver_VerifySpec_MintFails(t *testing.T) {
	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOAuth2,
			Config: map[string]string{}, // Missing credentials
		},
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	err := d.VerifySpec(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec verification failed")
}

func TestOAuth2Driver_VerifySpec_CustomHeader(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "custom-token",
			"token_type":   "Bearer",
		})
	}))
	defer tokenServer.Close()

	verifyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "custom-token", r.Header.Get("X-Api-Key"))
		assert.Empty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer verifyServer.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":        "test-id",
				"client_secret":    "test-secret",
				"token_url":        tokenServer.URL,
				"verify_url":       verifyServer.URL,
				"auth_header_type": "custom_header",
				"auth_header_name": "X-Api-Key",
			},
		},
		httpClient: tokenServer.Client(),
	}
	d.httpClient.Transport = tokenServer.Client().Transport

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	err := d.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestOAuth2Driver_VerifySpec_TokenAuthHeader(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok-123",
			"token_type":   "Bearer",
		})
	}))
	defer tokenServer.Close()

	verifyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Token tok-123", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer verifyServer.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeOAuth2,
			Config: map[string]string{
				"client_id":        "test-id",
				"client_secret":    "test-secret",
				"token_url":        tokenServer.URL,
				"verify_url":       verifyServer.URL,
				"auth_header_type": "token",
			},
		},
		httpClient: tokenServer.Client(),
	}
	d.httpClient.Transport = tokenServer.Client().Transport

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	err := d.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

// =============================================================================
// BuildAuthHeaders Tests
// =============================================================================

func TestBuildOAuth2AuthHeaders(t *testing.T) {
	tests := []struct {
		name          string
		config        map[string]string
		token         string
		expectHeader  string
		expectValue   string
		noAuthzHeader bool
	}{
		{
			name:         "default bearer",
			config:       map[string]string{},
			token:        "tok-123",
			expectHeader: "Authorization",
			expectValue:  "Bearer tok-123",
		},
		{
			name:         "explicit bearer",
			config:       map[string]string{"auth_header_type": "bearer"},
			token:        "tok-123",
			expectHeader: "Authorization",
			expectValue:  "Bearer tok-123",
		},
		{
			name:         "token type",
			config:       map[string]string{"auth_header_type": "token"},
			token:        "tok-123",
			expectHeader: "Authorization",
			expectValue:  "Token tok-123",
		},
		{
			name:          "custom header",
			config:        map[string]string{"auth_header_type": "custom_header", "auth_header_name": "X-Api-Key"},
			token:         "tok-123",
			expectHeader:  "X-Api-Key",
			expectValue:   "tok-123",
			noAuthzHeader: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := buildOAuth2AuthHeaders(tt.config, tt.token)
			assert.Equal(t, tt.expectValue, headers[tt.expectHeader])
			assert.Equal(t, "application/json", headers["Accept"])
			if tt.noAuthzHeader {
				_, hasAuth := headers["Authorization"]
				assert.False(t, hasAuth)
			}
		})
	}
}

// =============================================================================
// URL Validator Tests
// =============================================================================

func TestValidateOAuth2TokenURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"https://identity.pagerduty.com/oauth/token", false, ""},
		{"https://custom.example.com/token", false, ""},
		{"http://example.com/token", true, "must use https://"},
		{"ftp://example.com/token", true, "must use https://"},
		{"https://", true, "must include a host"},
		{"not-a-url", true, "must use https://"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateOAuth2TokenURL(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateOAuth2HTTPSURL_TLSSkipVerify(t *testing.T) {
	// HTTP allowed when tlsSkipVerify is true
	require.NoError(t, validateOAuth2HTTPSURL("http://auth.local/token", "token_url", true))
	// HTTPS still works
	require.NoError(t, validateOAuth2HTTPSURL("https://auth.local/token", "token_url", true))
	// FTP still rejected
	require.Error(t, validateOAuth2HTTPSURL("ftp://auth.local/token", "token_url", true))
}

func TestValidateOAuth2SafeURL_SSRF(t *testing.T) {
	// Public hostnames pass.
	require.NoError(t, validateOAuth2SafeURL("https://github.com/login/oauth/authorize", "auth_url", false))
	// IP literals in blocked ranges are rejected in production.
	for _, blocked := range []string{
		"https://127.0.0.1/x", "https://10.0.0.1/x", "https://192.168.1.1/x",
		"https://169.254.169.254/latest/meta-data/", "https://[::1]/x",
	} {
		require.Error(t, validateOAuth2SafeURL(blocked, "auth_url", false), blocked)
	}
	// tls_skip_verify allows loopback for dev/test.
	require.NoError(t, validateOAuth2SafeURL("https://127.0.0.1/x", "auth_url", true))
}

// =============================================================================
// Authorization-code flow
// =============================================================================

func TestOAuth2Driver_ExchangeAuthorizationCode(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		assert.Equal(t, "the-code", r.Form.Get("code"))
		assert.Equal(t, "http://127.0.0.1:8765/callback", r.Form.Get("redirect_uri"))
		assert.Equal(t, "cid", r.Form.Get("client_id"))
		assert.Equal(t, "csecret", r.Form.Get("client_secret"))
		assert.Equal(t, "the-verifier", r.Form.Get("code_verifier"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":             "at-1",
			"refresh_token":            "rt-1",
			"expires_in":               28800,
			"refresh_token_expires_in": 15897600,
			"token_type":               "bearer",
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{
		credSource: &credential.CredSource{Type: credential.SourceTypeOAuth2, Config: map[string]string{"token_url": server.URL}},
		httpClient: server.Client(),
	}
	spec := &credential.CredSpec{
		Name:   "gh",
		Type:   credential.TypeOAuthBearerToken,
		Config: map[string]string{"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret"},
	}

	sealed, err := d.ExchangeAuthorizationCode(context.Background(), spec, "the-code", "http://127.0.0.1:8765/callback", "the-verifier")
	require.NoError(t, err)
	assert.Equal(t, "rt-1", sealed["refresh_token"])
	exp, perr := time.Parse(time.RFC3339, sealed["refresh_token_expires_at"])
	require.NoError(t, perr)
	assert.True(t, exp.After(time.Now()))
}

func TestOAuth2Driver_ExchangeAuthorizationCode_ProviderError(t *testing.T) {
	// GitHub reports failures as HTTP 200 with an error body.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":             "bad_verification_code",
			"error_description": "The code passed is incorrect or expired.",
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{"client_id": "cid", "client_secret": "csecret"}}

	_, err := d.ExchangeAuthorizationCode(context.Background(), spec, "bad", "http://127.0.0.1:1/cb", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad_verification_code")
	assert.Contains(t, err.Error(), "incorrect or expired")
}

func TestOAuth2Driver_ExchangeAuthorizationCode_NoRefreshToken(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "static-at", "token_type": "bearer"})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{"client_id": "cid", "client_secret": "csecret"}}

	sealed, err := d.ExchangeAuthorizationCode(context.Background(), spec, "c", "http://127.0.0.1:1/cb", "")
	require.NoError(t, err)
	assert.Equal(t, "static-at", sealed["access_token"])
	assert.Empty(t, sealed["refresh_token"])
}

func TestOAuth2Driver_MintFromRefreshToken_Rotating(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.Form.Get("grant_type"))
		assert.Equal(t, "rt-old", r.Form.Get("refresh_token"))
		assert.Equal(t, "cid", r.Form.Get("client_id"))
		assert.Equal(t, "csecret", r.Form.Get("client_secret"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":             "at-new",
			"refresh_token":            "rt-new", // rotated
			"expires_in":               28800,
			"refresh_token_expires_in": 15897600, // ~6 months, reset window
			"token_type":               "bearer",
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret", "refresh_token": "rt-old",
	}}

	rawData, _, ttl, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "at-new", rawData["api_key"])
	assert.Equal(t, 28800*time.Second, ttl)
	// Rotated token is surfaced under the reserved key for the minting layer.
	assert.Equal(t, "rt-new", rawData[credential.RawRotatedRefreshTokenKey])
	// The reset refresh-token window is surfaced too, as a future RFC3339 expiry.
	rotatedExp, ok := rawData[credential.RawRotatedRefreshTokenExpiresAtKey].(string)
	require.True(t, ok, "rotated refresh-token expiry must be surfaced")
	exp, perr := time.Parse(time.RFC3339, rotatedExp)
	require.NoError(t, perr)
	assert.True(t, exp.After(time.Now().Add(180*24*time.Hour-time.Hour)), "expiry should reflect the reset ~6-month window")
}

func TestOAuth2Driver_MintFromRefreshToken_RotatingWithoutExpiry(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rotates the refresh token but returns no refresh_token_expires_in.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "at-new",
			"refresh_token": "rt-new",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret", "refresh_token": "rt-old",
	}}

	rawData, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "rt-new", rawData[credential.RawRotatedRefreshTokenKey])
	// No expiry surfaced when the provider omits refresh_token_expires_in.
	_, hasExp := rawData[credential.RawRotatedRefreshTokenExpiresAtKey]
	assert.False(t, hasExp)
}

func TestOAuth2Driver_MintFromRefreshToken_NonRotating(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No refresh_token in the response → stable token, no write-back.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "at-1", "expires_in": 3600})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "g", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret", "refresh_token": "rt-stable",
	}}

	rawData, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "at-1", rawData["api_key"])
	_, has := rawData[credential.RawRotatedRefreshTokenKey]
	assert.False(t, has)
}

func TestOAuth2Driver_MintFromRefreshToken_NotConnected(t *testing.T) {
	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": "https://example.invalid/token"}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret"}}

	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestOAuth2Driver_MintFromRefreshToken_StaticAccessToken(t *testing.T) {
	// No refresh_token but a sealed static access_token (no-refresh provider): no HTTP call.
	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": "https://example.invalid/token"}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{"auth_method": "authorization_code", "access_token": "static-token"}}

	rawData, _, ttl, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "static-token", rawData["api_key"])
	assert.Equal(t, time.Duration(0), ttl)
}

func TestOAuth2Driver_MintFromRefreshToken_InvalidGrant_HTTP400(t *testing.T) {
	// RFC 6749 standard rejection: HTTP 400 with an error body.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_grant", "error_description": "token expired"})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret", "refresh_token": "rt-dead",
	}}

	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.True(t, errors.Is(err, credential.ErrRefreshTokenRejected), "expected ErrRefreshTokenRejected, got %v", err)
}

func TestOAuth2Driver_MintFromRefreshToken_InvalidGrant_HTTP200(t *testing.T) {
	// GitHub-style rejection: HTTP 200 with an error body.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_grant"})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret", "refresh_token": "rt-dead",
	}}

	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.True(t, errors.Is(err, credential.ErrRefreshTokenRejected), "expected ErrRefreshTokenRejected, got %v", err)
}

func TestOAuth2Driver_MintFromRefreshToken_NonGrantError_NotRejection(t *testing.T) {
	// A non-grant error (HTTP 200 + a different code) must NOT be classified as a
	// refresh-token rejection, so the minting layer does not retry it.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "temporarily_unavailable"})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret", "refresh_token": "rt",
	}}

	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.False(t, errors.Is(err, credential.ErrRefreshTokenRejected), "non-grant error must not be a rejection: %v", err)
}

func TestOAuth2Driver_MintFromRefreshToken_InvalidClient_NotRejection(t *testing.T) {
	// HTTP 401 invalid_client (wrong client_secret) must NOT be classified as a
	// refresh-token rejection — the token is fine, the client creds are wrong.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid_client"})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "client_secret": "wrong", "refresh_token": "rt",
	}}

	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.False(t, errors.Is(err, credential.ErrRefreshTokenRejected), "invalid_client must not be a refresh-token rejection: %v", err)
}

func TestOAuth2Driver_MintFromRefreshToken_SlowDown400_NotRejection(t *testing.T) {
	// HTTP 400 with a non-grant code (slow_down) must NOT be a rejection, even
	// though the status is 400 — classification is by the parsed error code.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "slow_down"})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: server.Client()}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "client_secret": "csecret", "refresh_token": "rt",
	}}

	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.False(t, errors.Is(err, credential.ErrRefreshTokenRejected), "slow_down 400 must not be a refresh-token rejection: %v", err)
}

func TestOAuth2Driver_BuildAuthorizeURL(t *testing.T) {
	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{
		"auth_url": "https://github.com/login/oauth/authorize",
	}}}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "scopes": "repo,read:org",
	}}

	raw, err := d.BuildAuthorizeURL(spec, "http://127.0.0.1:8765/callback", "the-state", "the-challenge")
	require.NoError(t, err)

	u, err := url.Parse(raw)
	require.NoError(t, err)
	assert.Equal(t, "github.com", u.Host)
	q := u.Query()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "cid", q.Get("client_id"))
	assert.Equal(t, "http://127.0.0.1:8765/callback", q.Get("redirect_uri"))
	assert.Equal(t, "the-state", q.Get("state"))
	assert.Equal(t, "repo read:org", q.Get("scope")) // comma normalized to space
	assert.Equal(t, "the-challenge", q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
}

func TestOAuth2Driver_BuildAuthorizeURL_MissingAuthURL(t *testing.T) {
	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{}}}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{"client_id": "cid"}}

	_, err := d.BuildAuthorizeURL(spec, "http://127.0.0.1:1/cb", "s", "c")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_url")
}

func TestOAuth2Driver_BuildAuthorizeURL_PKCEDisabled(t *testing.T) {
	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{
		"auth_url": "https://github.com/login/oauth/authorize",
	}}}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "client_id": "cid", "pkce": "false",
	}}

	raw, err := d.BuildAuthorizeURL(spec, "http://127.0.0.1:8765/callback", "s", "the-challenge")
	require.NoError(t, err)
	u, err := url.Parse(raw)
	require.NoError(t, err)
	// pkce=false omits the challenge even when one is passed.
	assert.Empty(t, u.Query().Get("code_challenge"))
	assert.Empty(t, u.Query().Get("code_challenge_method"))
}

func TestOAuth2Driver_MintFromRefreshToken_StaticAccessToken_Expiring(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": "https://example.invalid/token"}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "access_token": "static-token", "access_token_expires_at": exp,
	}}

	rawData, _, ttl, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "static-token", rawData["api_key"])
	// TTL derived from access_token_expires_at (not the hardcoded 0).
	assert.InDelta(t, (2 * time.Hour).Seconds(), ttl.Seconds(), 60)
}

func TestOAuth2Driver_MintFromRefreshToken_MissingClientCreds(t *testing.T) {
	// A connected spec (refresh_token sealed) but no client credentials must fail
	// fast with a clear error instead of a wasted token-endpoint round-trip.
	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": "https://example.invalid/token"}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{
		"auth_method": "authorization_code", "refresh_token": "rt",
	}}

	_, _, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing client_id or client_secret")
}

// (connect-gating moved to the oauth_bearer_token credential type; see
// credential/types/oauth_bearer_token_test.go)

// =============================================================================
// Identity metadata (extractMetadata)
// =============================================================================

func TestOAuth2Driver_ExtractMetadata_JWTDefaultSub(t *testing.T) {
	// metadata_fields unset → defaults to "sub"; the JWT access token is decoded.
	jwt := mintTestJWT(`{"sub":"alice@example.com","email":"alice@corp.com"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": jwt, "expires_in": 3600})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"client_id": "c", "client_secret": "x"}}

	_, metadata, _, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", metadata["sub"])
	_, hasEmail := metadata["email"]
	assert.False(t, hasEmail, "only the default sub field should be captured")
}

func TestOAuth2Driver_ExtractMetadata_JWTConfiguredFields(t *testing.T) {
	jwt := mintTestJWT(`{"sub":"1234567890","email":"u@example.com","scope":"repo"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": jwt, "expires_in": 3600})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{
		"token_url": server.URL, "metadata_fields": "sub,email",
	}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"client_id": "c", "client_secret": "x"}}

	_, metadata, _, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "1234567890", metadata["sub"])
	assert.Equal(t, "u@example.com", metadata["email"])
	_, hasScope := metadata["scope"]
	assert.False(t, hasScope, "scope not in metadata_fields")
}

func TestOAuth2Driver_ExtractMetadata_Introspection(t *testing.T) {
	// Opaque token → call the introspection/userinfo endpoint at mint.
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer opaque-tok", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"login": "octocat", "id": 583231, "email": "o@gh.com"})
	}))
	defer userinfo.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "opaque-tok", "expires_in": 3600})
	}))
	defer tokenSrv.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{
		"token_url": tokenSrv.URL, "introspection_url": userinfo.URL, "metadata_fields": "login,email,id",
	}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "gh", Config: map[string]string{"client_id": "c", "client_secret": "x"}}

	_, metadata, _, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "octocat", metadata["login"])
	assert.Equal(t, "o@gh.com", metadata["email"])
	assert.Equal(t, "583231", metadata["id"], "numeric claim is stringified")
}

func TestOAuth2Driver_ExtractMetadata_OpaqueNoIntrospection(t *testing.T) {
	// Opaque token, no introspection_url → no metadata (can't derive a subject).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "opaque-xyz", "expires_in": 3600})
	}))
	defer server.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": server.URL}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"client_id": "c", "client_secret": "x"}}

	_, metadata, _, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Nil(t, metadata)
}

func TestOAuth2DriverFactory_ValidateConfig_IntrospectionURL_SSRF(t *testing.T) {
	f := &OAuth2DriverFactory{}
	err := f.ValidateConfig(map[string]string{
		"token_url":         "https://auth.example.com/token",
		"introspection_url": "https://169.254.169.254/latest/meta-data/",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not target a loopback/private/link-local address")
}

func TestOAuth2Driver_ExtractMetadata_IntrospectionURL_SpecLevelIgnored(t *testing.T) {
	// A spec-level introspection_url must be ignored — it is source-only so it
	// stays under the source SSRF guard and can't be injected per spec.
	called := false
	userinfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		json.NewEncoder(w).Encode(map[string]interface{}{"login": "octocat"})
	}))
	defer userinfo.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "opaque-tok", "expires_in": 3600})
	}))
	defer tokenSrv.Close()

	d := &OAuth2Driver{credSource: &credential.CredSource{Config: map[string]string{"token_url": tokenSrv.URL}}, httpClient: http.DefaultClient}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{
		"client_id": "c", "client_secret": "x",
		"introspection_url": userinfo.URL, // spec-level — must be ignored
		"metadata_fields":   "login",
	}}

	_, metadata, _, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.False(t, called, "spec-level introspection_url must not be called")
	assert.Nil(t, metadata, "opaque token + no source introspection_url → no metadata")
}
