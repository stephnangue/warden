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
	f := NewOAuth2DriverFactory(PagerDutyOAuth2Provider)
	assert.Equal(t, credential.SourceTypePagerDutyOAuth, f.Type())
}

func TestOAuth2DriverFactory_SensitiveConfigFields(t *testing.T) {
	f := NewOAuth2DriverFactory(PagerDutyOAuth2Provider)
	fields := f.SensitiveConfigFields()
	assert.Equal(t, []string{"client_secret"}, fields)
}

func TestOAuth2DriverFactory_InferCredentialType(t *testing.T) {
	f := NewOAuth2DriverFactory(PagerDutyOAuth2Provider)
	ct, err := f.InferCredentialType(map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeOAuthBearerToken, ct)
}

func TestOAuth2DriverFactory_ValidateConfig(t *testing.T) {
	f := NewOAuth2DriverFactory(PagerDutyOAuth2Provider)

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
			},
			wantErr: false,
		},
		{
			name: "valid config with custom token_url",
			config: map[string]string{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     "https://custom.example.com/oauth/token",
			},
			wantErr: false,
		},
		{
			name: "missing client_id",
			config: map[string]string{
				"client_secret": "test-client-secret",
			},
			wantErr: true,
			errMsg:  "client_id",
		},
		{
			name: "missing client_secret",
			config: map[string]string{
				"client_id": "test-client-id",
			},
			wantErr: true,
			errMsg:  "client_secret",
		},
		{
			name:    "missing both",
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
	f := NewOAuth2DriverFactory(PagerDutyOAuth2Provider)
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := f.Create(map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
	}, log)
	require.NoError(t, err)
	require.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypePagerDutyOAuth, driver.Type())
}

// =============================================================================
// Driver Tests
// =============================================================================

func createTestOAuth2Driver(t *testing.T, config map[string]string) *OAuth2Driver {
	t.Helper()
	f := NewOAuth2DriverFactory(PagerDutyOAuth2Provider)
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := f.Create(config, log)
	require.NoError(t, err)
	return driver.(*OAuth2Driver)
}

func TestOAuth2Driver_Type(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
	})
	assert.Equal(t, credential.SourceTypePagerDutyOAuth, d.Type())
}

func TestOAuth2Driver_Cleanup(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
	})
	assert.NoError(t, d.Cleanup(context.Background()))
}

func TestOAuth2Driver_Revoke_NoOp(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
	})
	assert.NoError(t, d.Revoke(context.Background(), "any-lease-id"))
	assert.NoError(t, d.Revoke(context.Background(), ""))
}

func TestOAuth2Driver_NotRotatable(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
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
		provider: PagerDutyOAuth2Provider,
		credSource: &credential.CredSource{
			Type: credential.SourceTypePagerDutyOAuth,
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
		// Default scope for PagerDuty is empty, so scope param should not be set
		assert.Empty(t, r.Form.Get("scope"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   1800,
		})
	}))
	defer server.Close()

	d := &OAuth2Driver{
		provider: PagerDutyOAuth2Provider,
		credSource: &credential.CredSource{
			Type: credential.SourceTypePagerDutyOAuth,
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
		Type:   credential.TypeOAuthBearerToken,
		Config: map[string]string{},
	}

	rawData, ttl, _, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "test-token", rawData["api_key"])
	assert.Equal(t, 1800*time.Second, ttl)
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
		provider: PagerDutyOAuth2Provider,
		credSource: &credential.CredSource{
			Type: credential.SourceTypePagerDutyOAuth,
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
		provider: PagerDutyOAuth2Provider,
		credSource: &credential.CredSource{
			Type:   credential.SourceTypePagerDutyOAuth,
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
		provider: PagerDutyOAuth2Provider,
		credSource: &credential.CredSource{
			Type: credential.SourceTypePagerDutyOAuth,
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
		provider: PagerDutyOAuth2Provider,
		credSource: &credential.CredSource{
			Type: credential.SourceTypePagerDutyOAuth,
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
		provider: PagerDutyOAuth2Provider,
		credSource: &credential.CredSource{
			Type: credential.SourceTypePagerDutyOAuth,
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

	provider := OAuth2ProviderConfig{
		SourceType:      credential.SourceTypePagerDutyOAuth,
		DisplayName:     "PagerDuty",
		DefaultTokenURL: tokenServer.URL,
		VerifyURL:       verifyServer.URL,
		VerifyMethod:    http.MethodGet,
		BuildAuthHeaders: func(apiKey string) map[string]string {
			return map[string]string{
				"Authorization": "Bearer " + apiKey,
				"Accept":        "application/json",
			}
		},
	}

	d := &OAuth2Driver{
		provider: provider,
		credSource: &credential.CredSource{
			Type: credential.SourceTypePagerDutyOAuth,
			Config: map[string]string{
				"client_id":     "test-id",
				"client_secret": "test-secret",
				"token_url":     tokenServer.URL,
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

	provider := OAuth2ProviderConfig{
		SourceType:      credential.SourceTypePagerDutyOAuth,
		DisplayName:     "PagerDuty",
		DefaultTokenURL: tokenServer.URL,
		VerifyURL:       "", // No verification endpoint
	}

	d := &OAuth2Driver{
		provider: provider,
		credSource: &credential.CredSource{
			Type: credential.SourceTypePagerDutyOAuth,
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
		provider: PagerDutyOAuth2Provider,
		credSource: &credential.CredSource{
			Type:   credential.SourceTypePagerDutyOAuth,
			Config: map[string]string{}, // Missing credentials
		},
	}

	spec := &credential.CredSpec{Name: "test", Config: map[string]string{}}
	err := d.VerifySpec(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spec verification failed")
}

// =============================================================================
// GetTokenURL Tests
// =============================================================================

func TestOAuth2Driver_GetTokenURL_Default(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
	})
	assert.Equal(t, PagerDutyOAuth2Provider.DefaultTokenURL, d.getTokenURL())
}

func TestOAuth2Driver_GetTokenURL_Custom(t *testing.T) {
	d := createTestOAuth2Driver(t, map[string]string{
		"client_id":     "test-id",
		"client_secret": "test-secret",
		"token_url":     "https://custom.example.com/oauth/token",
	})
	assert.Equal(t, "https://custom.example.com/oauth/token", d.getTokenURL())
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
