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

// allAPIKeyProviders returns the 4 built-in API key provider configs for table-driven tests.
func allAPIKeyProviders() []APIKeyProviderConfig {
	return []APIKeyProviderConfig{
		AnthropicProvider, OpenAIProvider, MistralProvider, SlackProvider, PagerDutyProvider,
	}
}

// =============================================================================
// Factory Tests (parameterized)
// =============================================================================

func TestStaticAPIKeyDriverFactory_Type(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			f := NewStaticAPIKeyDriverFactory(p)
			assert.Equal(t, p.SourceType, f.Type())
		})
	}
}

func TestStaticAPIKeyDriverFactory_SensitiveConfigFields(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			f := NewStaticAPIKeyDriverFactory(p)
			assert.Nil(t, f.SensitiveConfigFields())
		})
	}
}

func TestStaticAPIKeyDriverFactory_ValidateConfig(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		f := NewStaticAPIKeyDriverFactory(p)

		t.Run(p.DisplayName+"/valid_empty_config", func(t *testing.T) {
			err := f.ValidateConfig(map[string]string{})
			assert.NoError(t, err)
		})

		t.Run(p.DisplayName+"/valid_explicit_url", func(t *testing.T) {
			err := f.ValidateConfig(map[string]string{"api_url": p.DefaultAPIURL})
			assert.NoError(t, err)
		})

		t.Run(p.DisplayName+"/valid_custom_url", func(t *testing.T) {
			err := f.ValidateConfig(map[string]string{"api_url": "https://custom.example.com"})
			assert.NoError(t, err)
		})

		t.Run(p.DisplayName+"/invalid_http_scheme", func(t *testing.T) {
			err := f.ValidateConfig(map[string]string{"api_url": "http://example.com"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must use https://")
		})

		t.Run(p.DisplayName+"/invalid_no_host", func(t *testing.T) {
			err := f.ValidateConfig(map[string]string{"api_url": "https://"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must include a host")
		})
	}
}

func TestStaticAPIKeyDriverFactory_Create(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			f := NewStaticAPIKeyDriverFactory(p)
			log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
			driver, err := f.Create(map[string]string{"api_url": p.DefaultAPIURL}, log)
			require.NoError(t, err)
			require.NotNil(t, driver)
			assert.Equal(t, p.SourceType, driver.Type())
		})
	}
}

func TestStaticAPIKeyDriverFactory_InferCredentialType(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			f := NewStaticAPIKeyDriverFactory(p)
			ct, err := f.InferCredentialType(map[string]string{})
			require.NoError(t, err)
			assert.Equal(t, credential.TypeAPIKey, ct)
		})
	}
}

// =============================================================================
// Driver Tests (parameterized)
// =============================================================================

func createTestDriver(t *testing.T, p APIKeyProviderConfig) *StaticAPIKeyDriver {
	t.Helper()
	f := NewStaticAPIKeyDriverFactory(p)
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := f.Create(map[string]string{}, log)
	require.NoError(t, err)
	return driver.(*StaticAPIKeyDriver)
}

func TestStaticAPIKeyDriver_Type(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			d := createTestDriver(t, p)
			assert.Equal(t, p.SourceType, d.Type())
		})
	}
}

func TestStaticAPIKeyDriver_Cleanup(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			d := createTestDriver(t, p)
			assert.NoError(t, d.Cleanup(context.Background()))
		})
	}
}

func TestStaticAPIKeyDriver_Revoke_NoOp(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			d := createTestDriver(t, p)
			assert.NoError(t, d.Revoke(context.Background(), "any-lease-id"))
			assert.NoError(t, d.Revoke(context.Background(), ""))
		})
	}
}

func TestStaticAPIKeyDriver_NotRotatable(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			d := createTestDriver(t, p)
			var sd credential.SourceDriver = d
			_, ok := sd.(credential.Rotatable)
			assert.False(t, ok, "%s should not implement credential.Rotatable", p.DisplayName)
		})
	}
}

func TestStaticAPIKeyDriver_MintCredential(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			d := createTestDriver(t, p)
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
		})
	}
}

func TestStaticAPIKeyDriver_MintCredential_EmptyKey(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			d := createTestDriver(t, p)
			spec := &credential.CredSpec{
				Name:   "test",
				Type:   credential.TypeAPIKey,
				Config: map[string]string{"api_key": ""},
			}
			_, _, _, err := d.MintCredential(context.Background(), spec)
			require.Error(t, err)
			assert.Contains(t, err.Error(), p.DisplayName+" API key")
		})
	}
}

func TestStaticAPIKeyDriver_GetAPIURL_Default(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			d := createTestDriver(t, p)
			assert.Equal(t, p.DefaultAPIURL, d.getAPIURL())
		})
	}
}

func TestStaticAPIKeyDriver_GetAPIURL_TrailingSlash(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			f := NewStaticAPIKeyDriverFactory(p)
			log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
			driver, _ := f.Create(map[string]string{"api_url": p.DefaultAPIURL + "/"}, log)
			d := driver.(*StaticAPIKeyDriver)
			assert.Equal(t, p.DefaultAPIURL, d.getAPIURL())
		})
	}
}

// =============================================================================
// Optional Metadata Tests
// =============================================================================

func TestStaticAPIKeyDriver_MintCredential_OptionalMetadata(t *testing.T) {
	t.Run("OpenAI copies organization_id and project_id", func(t *testing.T) {
		d := createTestDriver(t, OpenAIProvider)
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

	t.Run("Anthropic copies organization_id", func(t *testing.T) {
		d := createTestDriver(t, AnthropicProvider)
		spec := &credential.CredSpec{
			Name: "test",
			Config: map[string]string{
				"api_key":         "sk-ant-test",
				"organization_id": "org-123",
			},
		}
		rawData, _, _, err := d.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Equal(t, "org-123", rawData["organization_id"])
	})

	t.Run("Mistral copies organization_id", func(t *testing.T) {
		d := createTestDriver(t, MistralProvider)
		spec := &credential.CredSpec{
			Name: "test",
			Config: map[string]string{
				"api_key":         "sk-mistral-test",
				"organization_id": "org-123",
			},
		}
		rawData, _, _, err := d.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Equal(t, "org-123", rawData["organization_id"])
	})

	t.Run("Slack copies no optional metadata", func(t *testing.T) {
		d := createTestDriver(t, SlackProvider)
		spec := &credential.CredSpec{
			Name: "test",
			Config: map[string]string{
				"api_key":         "xoxb-test",
				"organization_id": "org-123",
			},
		}
		rawData, _, _, err := d.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Nil(t, rawData["organization_id"])
	})
}

// =============================================================================
// VerifySpec Tests (provider-specific due to different endpoints/headers)
// =============================================================================

func TestStaticAPIKeyDriver_VerifySpec(t *testing.T) {
	tests := []struct {
		provider       APIKeyProviderConfig
		expectedMethod string
		expectedPath   string
		checkHeaders   func(t *testing.T, r *http.Request)
	}{
		{
			provider:       AnthropicProvider,
			expectedMethod: http.MethodGet,
			expectedPath:   "/v1/models",
			checkHeaders: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "sk-valid-key", r.Header.Get("x-api-key"))
				assert.Equal(t, "2023-06-01", r.Header.Get("anthropic-version"))
			},
		},
		{
			provider:       OpenAIProvider,
			expectedMethod: http.MethodGet,
			expectedPath:   "/v1/models",
			checkHeaders: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "Bearer sk-valid-key", r.Header.Get("Authorization"))
			},
		},
		{
			provider:       MistralProvider,
			expectedMethod: http.MethodGet,
			expectedPath:   "/v1/models",
			checkHeaders: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "Bearer sk-valid-key", r.Header.Get("Authorization"))
			},
		},
		{
			provider:       SlackProvider,
			expectedMethod: http.MethodPost,
			expectedPath:   "/auth.test",
			checkHeaders: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "Bearer sk-valid-key", r.Header.Get("Authorization"))
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			},
		},
		{
			provider:       PagerDutyProvider,
			expectedMethod: http.MethodGet,
			expectedPath:   "/users/me",
			checkHeaders: func(t *testing.T, r *http.Request) {
				assert.Equal(t, "Bearer sk-valid-key", r.Header.Get("Authorization"))
				assert.Equal(t, "application/json", r.Header.Get("Accept"))
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.provider.DisplayName, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.expectedMethod, r.Method)
				assert.Equal(t, tt.expectedPath, r.URL.Path)
				tt.checkHeaders(t, r)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"ok":true}`))
			}))
			defer server.Close()

			d := &StaticAPIKeyDriver{
				provider: tt.provider,
				credSource: &credential.CredSource{
					Type:   tt.provider.SourceType,
					Config: map[string]string{"api_url": server.URL},
				},
				httpClient: server.Client(),
			}

			spec := &credential.CredSpec{
				Name:   "test-verify",
				Config: map[string]string{"api_key": "sk-valid-key"},
			}
			err := d.VerifySpec(context.Background(), spec)
			assert.NoError(t, err)
		})
	}
}

func TestStaticAPIKeyDriver_VerifySpec_InvalidKey(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid_auth"}`))
			}))
			defer server.Close()

			d := &StaticAPIKeyDriver{
				provider: p,
				credSource: &credential.CredSource{
					Type:   p.SourceType,
					Config: map[string]string{"api_url": server.URL},
				},
				httpClient: server.Client(),
			}

			spec := &credential.CredSpec{
				Name:   "test-verify",
				Config: map[string]string{"api_key": "sk-invalid"},
			}
			err := d.VerifySpec(context.Background(), spec)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "verification failed")
		})
	}
}

func TestStaticAPIKeyDriver_VerifySpec_EmptyKey(t *testing.T) {
	for _, p := range allAPIKeyProviders() {
		t.Run(p.DisplayName, func(t *testing.T) {
			d := createTestDriver(t, p)
			spec := &credential.CredSpec{
				Name:   "test-verify",
				Config: map[string]string{"api_key": ""},
			}
			err := d.VerifySpec(context.Background(), spec)
			require.Error(t, err)
			assert.Contains(t, err.Error(), p.DisplayName+" API key")
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
