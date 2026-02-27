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

func TestOpenAIDriverFactory_Type(t *testing.T) {
	factory := &OpenAIDriverFactory{}
	assert.Equal(t, credential.SourceTypeOpenAI, factory.Type())
}

func TestOpenAIDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &OpenAIDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Nil(t, fields, "source has no secrets — they live in the spec")
}

func TestOpenAIDriverFactory_ValidateConfig(t *testing.T) {
	factory := &OpenAIDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid empty config (uses default api_url)",
			config:  map[string]string{},
			wantErr: false,
		},
		{
			name:    "valid explicit api_url",
			config:  map[string]string{"api_url": "https://api.openai.com"},
			wantErr: false,
		},
		{
			name:    "valid custom api_url",
			config:  map[string]string{"api_url": "https://openai.example.com"},
			wantErr: false,
		},
		{
			name:    "invalid api_url scheme",
			config:  map[string]string{"api_url": "http://api.openai.com"},
			wantErr: true,
			errMsg:  "must use https://",
		},
		{
			name:    "invalid api_url no host",
			config:  map[string]string{"api_url": "https://"},
			wantErr: true,
			errMsg:  "must include a host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOpenAIDriverFactory_Create(t *testing.T) {
	factory := &OpenAIDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := factory.Create(map[string]string{
		"api_url": "https://api.openai.com",
	}, log)
	require.NoError(t, err)
	assert.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeOpenAI, driver.Type())
}

func TestOpenAIDriver_Type(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeOpenAI, driver.Type())
}

func TestOpenAIDriver_Cleanup(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}
	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}

func TestOpenAIDriver_Revoke_NoOp(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
	}
	// OpenAI API keys are static — revoke is a no-op
	err := driver.Revoke(context.Background(), "any-lease-id")
	assert.NoError(t, err)

	err = driver.Revoke(context.Background(), "")
	assert.NoError(t, err)
}

func TestOpenAIDriver_NotRotatable(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
	}
	// OpenAIDriver should not implement Rotatable
	var sd credential.SourceDriver = driver
	_, ok := sd.(credential.Rotatable)
	assert.False(t, ok, "OpenAIDriver should not implement credential.Rotatable")
}

func TestOpenAIDriver_MintCredential(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{"api_url": "https://api.openai.com"},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-openai",
		Type: credential.TypeAIAPIKey,
		Config: map[string]string{
			"api_key": "sk-test-key-123",
		},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "sk-test-key-123", rawData["api_key"])
	assert.Equal(t, time.Duration(0), ttl)
	assert.Equal(t, "", leaseID)
}

func TestOpenAIDriver_MintCredential_EmptyKey(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-openai",
		Type: credential.TypeAIAPIKey,
		Config: map[string]string{
			"api_key": "",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no OpenAI API key configured")
}

func TestOpenAIDriver_MintCredential_WithOrganizationID(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-openai",
		Type: credential.TypeAIAPIKey,
		Config: map[string]string{
			"api_key":         "sk-test-key-123",
			"organization_id": "org-456",
		},
	}

	rawData, _, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "sk-test-key-123", rawData["api_key"])
	assert.Equal(t, "org-456", rawData["organization_id"])
}

func TestOpenAIDriver_MintCredential_WithProjectID(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-openai",
		Type: credential.TypeAIAPIKey,
		Config: map[string]string{
			"api_key":    "sk-test-key-123",
			"project_id": "proj-789",
		},
	}

	rawData, _, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "sk-test-key-123", rawData["api_key"])
	assert.Equal(t, "proj-789", rawData["project_id"])
}

func TestOpenAIDriver_MintCredential_WithAllOptionalFields(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-openai",
		Type: credential.TypeAIAPIKey,
		Config: map[string]string{
			"api_key":         "sk-test-key-123",
			"organization_id": "org-456",
			"project_id":      "proj-789",
		},
	}

	rawData, _, _, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "sk-test-key-123", rawData["api_key"])
	assert.Equal(t, "org-456", rawData["organization_id"])
	assert.Equal(t, "proj-789", rawData["project_id"])
}

func TestOpenAIDriver_VerifySpec(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/models", r.URL.Path)
		assert.Equal(t, "Bearer sk-valid-key", r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	defer server.Close()

	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{"api_url": server.URL},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-verify",
		Type: credential.TypeAIAPIKey,
		Config: map[string]string{
			"api_key": "sk-valid-key",
		},
	}

	err := driver.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestOpenAIDriver_VerifySpec_InvalidKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}`))
	}))
	defer server.Close()

	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{"api_url": server.URL},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-verify",
		Type: credential.TypeAIAPIKey,
		Config: map[string]string{
			"api_key": "sk-invalid-key",
		},
	}

	err := driver.VerifySpec(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestOpenAIDriver_VerifySpec_EmptyKey(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}

	spec := &credential.CredSpec{
		Name: "test-verify",
		Type: credential.TypeAIAPIKey,
		Config: map[string]string{
			"api_key": "",
		},
	}

	err := driver.VerifySpec(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no OpenAI API key configured")
}

func TestOpenAIDriver_GetAPIURL(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{"api_url": "https://api.openai.com/"},
		},
	}
	// getAPIURL trims trailing slash
	assert.Equal(t, "https://api.openai.com", driver.getAPIURL())
}

func TestOpenAIDriver_GetAPIURL_Default(t *testing.T) {
	driver := &OpenAIDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeOpenAI,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, DefaultOpenAIAPIURL, driver.getAPIURL())
}

func TestValidateOpenAIURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"https://api.openai.com", false, ""},
		{"https://openai.example.com", false, ""},
		{"http://api.openai.com", true, "must use https://"},
		{"ftp://api.openai.com", true, "must use https://"},
		{"https://", true, "must include a host"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateOpenAIURL(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
