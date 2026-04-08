package drivers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			name: "missing client_id",
			config: map[string]string{
				"client_secret": "test-client-secret",
				"token_url":     "https://auth.example.com/oauth/token",
			},
			wantErr: true,
			errMsg:  "client_id",
		},
		{
			name: "missing client_secret",
			config: map[string]string{
				"client_id": "test-client-id",
				"token_url": "https://auth.example.com/oauth/token",
			},
			wantErr: true,
			errMsg:  "client_secret",
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
				"client_id":      "test-client-id",
				"client_secret":  "test-client-secret",
				"token_url":      "https://auth.example.com/token",
				"verify_method":  "DELETE",
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
				"client_id":              "test-client-id",
				"client_secret":          "test-client-secret",
				"token_url":              "https://auth.example.com/token",
				"token_param.resource":   "urn:dtaccount:abc123",
				"token_param.audience":   "https://api.example.com",
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
				"client_id":              "test-client-id",
				"client_secret":          "test-client-secret",
				"token_url":              "https://auth.example.com/token",
				"token_param.client_id":  "override",
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

	rawData, ttl, leaseID, err := d.MintCredential(context.Background(), spec)
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

	rawData, ttl, _, err := d.MintCredential(context.Background(), spec)
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

	rawData, _, _, err := d.MintCredential(context.Background(), spec)
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

	_, ttl, _, err := d.MintCredential(context.Background(), spec)
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
	_, _, _, err := d.MintCredential(context.Background(), spec)
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
	_, _, _, err := d.MintCredential(context.Background(), spec)
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
	_, _, _, err := d.MintCredential(context.Background(), spec)
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
	_, _, _, err := d.MintCredential(context.Background(), spec)
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
	_, _, _, err := d.MintCredential(context.Background(), spec)
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
		name           string
		config         map[string]string
		token          string
		expectHeader   string
		expectValue    string
		noAuthzHeader  bool
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
