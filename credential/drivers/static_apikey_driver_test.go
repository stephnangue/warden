package drivers

import (
	"context"
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

func TestStaticAPIKeyDriverFactory_Type(t *testing.T) {
	f := &StaticAPIKeyDriverFactory{}
	assert.Equal(t, credential.SourceTypeAPIKey, f.Type())
}

func TestStaticAPIKeyDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &StaticAPIKeyDriverFactory{}
	assert.Nil(t, f.SensitiveConfigFields())
}

func TestStaticAPIKeyDriverFactory_InferCredentialType(t *testing.T) {
	f := &StaticAPIKeyDriverFactory{}
	ct, err := f.InferCredentialType(map[string]string{})
	require.NoError(t, err)
	assert.Equal(t, credential.TypeAPIKey, ct)
}

func TestStaticAPIKeyDriverFactory_ValidateConfig(t *testing.T) {
	f := &StaticAPIKeyDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid empty config",
			config:  map[string]string{},
			wantErr: false,
		},
		{
			name:    "valid with api_url",
			config:  map[string]string{"api_url": "https://api.openai.com"},
			wantErr: false,
		},
		{
			name: "valid with all optional fields",
			config: map[string]string{
				"api_url":           "https://api.anthropic.com",
				"verify_endpoint":   "/v1/models",
				"verify_method":     "GET",
				"auth_header_type":  "custom_header",
				"auth_header_name":  "x-api-key",
				"extra_headers":     "anthropic-version:2023-06-01",
				"optional_metadata": "organization_id",
				"display_name":      "Anthropic",
			},
			wantErr: false,
		},
		{
			name:    "invalid api_url - http scheme",
			config:  map[string]string{"api_url": "http://example.com"},
			wantErr: true,
			errMsg:  "must use https://",
		},
		{
			name:    "invalid api_url - no host",
			config:  map[string]string{"api_url": "https://"},
			wantErr: true,
			errMsg:  "must include a host",
		},
		{
			name:    "invalid verify_method",
			config:  map[string]string{"verify_method": "DELETE"},
			wantErr: true,
			errMsg:  "verify_method must be GET or POST",
		},
		{
			name:    "invalid auth_header_type",
			config:  map[string]string{"auth_header_type": "basic"},
			wantErr: true,
			errMsg:  "auth_header_type must be one of",
		},
		{
			name:    "custom_header without auth_header_name",
			config:  map[string]string{"auth_header_type": "custom_header"},
			wantErr: true,
			errMsg:  "auth_header_name is required",
		},
		{
			name: "custom_header with auth_header_name",
			config: map[string]string{
				"auth_header_type": "custom_header",
				"auth_header_name": "x-api-key",
			},
			wantErr: false,
		},
		{
			name:    "invalid extra_headers format",
			config:  map[string]string{"extra_headers": "no-colon"},
			wantErr: true,
			errMsg:  "expected key:value format",
		},
		{
			name:    "valid extra_headers",
			config:  map[string]string{"extra_headers": "anthropic-version:2023-06-01,x-custom:value"},
			wantErr: false,
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

func TestStaticAPIKeyDriverFactory_Create(t *testing.T) {
	f := &StaticAPIKeyDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := f.Create(map[string]string{"api_url": "https://api.openai.com"}, log)
	require.NoError(t, err)
	require.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeAPIKey, driver.Type())
}

// =============================================================================
// Driver Tests
// =============================================================================

func createTestAPIKeyDriver(t *testing.T, config map[string]string) *StaticAPIKeyDriver {
	t.Helper()
	f := &StaticAPIKeyDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := f.Create(config, log)
	require.NoError(t, err)
	return driver.(*StaticAPIKeyDriver)
}

func TestStaticAPIKeyDriver_Type(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{})
	assert.Equal(t, credential.SourceTypeAPIKey, d.Type())
}

func TestStaticAPIKeyDriver_Cleanup(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{})
	assert.NoError(t, d.Cleanup(context.Background()))
}

func TestStaticAPIKeyDriver_Revoke_NoOp(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{})
	assert.NoError(t, d.Revoke(context.Background(), "any-lease-id"))
	assert.NoError(t, d.Revoke(context.Background(), ""))
}

func TestStaticAPIKeyDriver_NotRotatable(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{})
	var sd credential.SourceDriver = d
	_, ok := sd.(credential.Rotatable)
	assert.False(t, ok, "StaticAPIKeyDriver should not implement credential.Rotatable")
}

func TestStaticAPIKeyDriver_MintCredential(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{})
	spec := &credential.CredSpec{
		Name:   "test",
		Type:   credential.TypeAPIKey,
		Config: map[string]string{"api_key": "sk-test-key-123"},
	}
	rawData, ttl, leaseID, err := d.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "sk-test-key-123", rawData["api_key"])
	assert.Equal(t, time.Duration(0), ttl)
	assert.Empty(t, leaseID)
}

func TestStaticAPIKeyDriver_MintCredential_EmptyKey(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{"display_name": "OpenAI"})
	spec := &credential.CredSpec{
		Name:   "test",
		Type:   credential.TypeAPIKey,
		Config: map[string]string{"api_key": ""},
	}
	_, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OpenAI API key")
}

func TestStaticAPIKeyDriver_MintCredential_DisplayName(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{})
	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{},
	}
	_, _, _, err := d.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API Key") // default display name
}

func TestStaticAPIKeyDriver_GetAPIURL(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{"api_url": "https://api.openai.com"})
	assert.Equal(t, "https://api.openai.com", d.getAPIURL())
}

func TestStaticAPIKeyDriver_GetAPIURL_TrailingSlash(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{"api_url": "https://api.openai.com/"})
	assert.Equal(t, "https://api.openai.com", d.getAPIURL())
}

func TestStaticAPIKeyDriver_GetAPIURL_Empty(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{})
	assert.Equal(t, "", d.getAPIURL())
}

// =============================================================================
// Optional Metadata Tests
// =============================================================================

func TestStaticAPIKeyDriver_MintCredential_OptionalMetadata(t *testing.T) {
	t.Run("copies configured metadata fields", func(t *testing.T) {
		d := createTestAPIKeyDriver(t, map[string]string{
			"optional_metadata": "organization_id,project_id",
		})
		spec := &credential.CredSpec{
			Name: "test",
			Config: map[string]string{
				"api_key":         "sk-test",
				"organization_id": "org-456",
				"project_id":      "proj-789",
			},
		}
		rawData, _, _, err := d.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Equal(t, "org-456", rawData["organization_id"])
		assert.Equal(t, "proj-789", rawData["project_id"])
	})

	t.Run("skips empty metadata fields", func(t *testing.T) {
		d := createTestAPIKeyDriver(t, map[string]string{
			"optional_metadata": "organization_id",
		})
		spec := &credential.CredSpec{
			Name:   "test",
			Config: map[string]string{"api_key": "sk-test"},
		}
		rawData, _, _, err := d.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Nil(t, rawData["organization_id"])
	})

	t.Run("no metadata when not configured", func(t *testing.T) {
		d := createTestAPIKeyDriver(t, map[string]string{})
		spec := &credential.CredSpec{
			Name: "test",
			Config: map[string]string{
				"api_key":         "sk-test",
				"organization_id": "org-123",
			},
		}
		rawData, _, _, err := d.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Nil(t, rawData["organization_id"])
	})
}

// =============================================================================
// VerifySpec Tests
// =============================================================================

func TestStaticAPIKeyDriver_VerifySpec_Bearer(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/models", r.URL.Path)
		assert.Equal(t, "Bearer sk-valid-key", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	d := &StaticAPIKeyDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAPIKey,
			Config: map[string]string{
				"api_url":         server.URL,
				"verify_endpoint": "/v1/models",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{"api_key": "sk-valid-key"},
	}
	err := d.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestStaticAPIKeyDriver_VerifySpec_CustomHeader(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/models", r.URL.Path)
		assert.Equal(t, "sk-valid-key", r.Header.Get("x-api-key"))
		assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
		assert.Empty(t, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := &StaticAPIKeyDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAPIKey,
			Config: map[string]string{
				"api_url":          server.URL,
				"verify_endpoint":  "/v1/models",
				"auth_header_type": "custom_header",
				"auth_header_name": "x-api-key",
				"extra_headers":    "anthropic-version:2023-06-01",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{"api_key": "sk-valid-key"},
	}
	err := d.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestStaticAPIKeyDriver_VerifySpec_PostMethod(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/auth.test", r.URL.Path)
		assert.Equal(t, "Bearer sk-valid-key", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := &StaticAPIKeyDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAPIKey,
			Config: map[string]string{
				"api_url":         server.URL,
				"verify_endpoint": "/auth.test",
				"verify_method":   "POST",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{"api_key": "sk-valid-key"},
	}
	err := d.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestStaticAPIKeyDriver_VerifySpec_NoVerifyEndpoint(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{})
	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{"api_key": "sk-test"},
	}
	err := d.VerifySpec(context.Background(), spec)
	assert.NoError(t, err) // skips verification
}

func TestStaticAPIKeyDriver_VerifySpec_InvalidKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_auth"}`))
	}))
	defer server.Close()

	d := &StaticAPIKeyDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAPIKey,
			Config: map[string]string{
				"api_url":         server.URL,
				"verify_endpoint": "/v1/models",
			},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{"api_key": "sk-invalid"},
	}
	err := d.VerifySpec(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestStaticAPIKeyDriver_VerifySpec_EmptyKey(t *testing.T) {
	d := createTestAPIKeyDriver(t, map[string]string{"display_name": "OpenAI"})
	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{"api_key": ""},
	}
	err := d.VerifySpec(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OpenAI API key")
}

// =============================================================================
// BuildAuthHeaders Tests
// =============================================================================

func TestBuildAPIKeyAuthHeaders(t *testing.T) {
	tests := []struct {
		name          string
		config        map[string]string
		apiKey        string
		expectHeader  string
		expectValue   string
		noAuthzHeader bool
	}{
		{
			name:         "default bearer",
			config:       map[string]string{},
			apiKey:       "sk-123",
			expectHeader: "Authorization",
			expectValue:  "Bearer sk-123",
		},
		{
			name:         "explicit bearer",
			config:       map[string]string{"auth_header_type": "bearer"},
			apiKey:       "sk-123",
			expectHeader: "Authorization",
			expectValue:  "Bearer sk-123",
		},
		{
			name:         "token type",
			config:       map[string]string{"auth_header_type": "token"},
			apiKey:       "sk-123",
			expectHeader: "Authorization",
			expectValue:  "Token sk-123",
		},
		{
			name:          "custom header",
			config:        map[string]string{"auth_header_type": "custom_header", "auth_header_name": "x-api-key"},
			apiKey:        "sk-123",
			expectHeader:  "x-api-key",
			expectValue:   "sk-123",
			noAuthzHeader: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := buildAPIKeyAuthHeaders(tt.config, tt.apiKey)
			assert.Equal(t, tt.expectValue, headers[tt.expectHeader])
			assert.Equal(t, "application/json", headers["Accept"])
			if tt.noAuthzHeader {
				_, hasAuth := headers["Authorization"]
				assert.False(t, hasAuth)
			}
		})
	}
}

func TestBuildAPIKeyAuthHeaders_ExtraHeaders(t *testing.T) {
	config := map[string]string{
		"auth_header_type": "custom_header",
		"auth_header_name": "x-api-key",
		"extra_headers":    "anthropic-version:2023-06-01,x-custom:value",
	}
	headers := buildAPIKeyAuthHeaders(config, "sk-test")
	assert.Equal(t, "sk-test", headers["x-api-key"])
	assert.Equal(t, "2023-06-01", headers["anthropic-version"])
	assert.Equal(t, "value", headers["x-custom"])
}

// =============================================================================
// ParseExtraHeaders Tests
// =============================================================================

func TestParseExtraHeaders(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "single pair",
			raw:  "anthropic-version:2023-06-01",
			want: map[string]string{"anthropic-version": "2023-06-01"},
		},
		{
			name: "multiple pairs",
			raw:  "key1:val1,key2:val2",
			want: map[string]string{"key1": "val1", "key2": "val2"},
		},
		{
			name: "with spaces",
			raw:  " key1 : val1 , key2 : val2 ",
			want: map[string]string{"key1": "val1", "key2": "val2"},
		},
		{
			name:    "invalid format",
			raw:     "no-colon",
			wantErr: true,
		},
		{
			name: "empty string",
			raw:  "",
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExtraHeaders(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// =============================================================================
// URL Validator Test
// =============================================================================

func TestValidateAPIKeyURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"https://api.example.com", false, ""},
		{"https://custom.example.com", false, ""},
		{"http://api.example.com", true, "must use https://"},
		{"ftp://api.example.com", true, "must use https://"},
		{"https://", true, "must include a host"},
		{"not-a-url", true, "must use https://"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateAPIKeyURL(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
