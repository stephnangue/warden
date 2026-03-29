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

func TestSlackDriverFactory_Type(t *testing.T) {
	factory := &SlackDriverFactory{}
	assert.Equal(t, credential.SourceTypeSlack, factory.Type())
}

func TestSlackDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &SlackDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Nil(t, fields, "source has no secrets — they live in the spec")
}

func TestSlackDriverFactory_ValidateConfig(t *testing.T) {
	factory := &SlackDriverFactory{}

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
			config:  map[string]string{"api_url": "https://slack.com/api"},
			wantErr: false,
		},
		{
			name:    "valid custom api_url",
			config:  map[string]string{"api_url": "https://slack.example.com"},
			wantErr: false,
		},
		{
			name:    "invalid api_url scheme",
			config:  map[string]string{"api_url": "http://slack.com/api"},
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

func TestSlackDriverFactory_Create(t *testing.T) {
	factory := &SlackDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	driver, err := factory.Create(map[string]string{
		"api_url": "https://slack.com/api",
	}, log)
	require.NoError(t, err)
	assert.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeSlack, driver.Type())
}

func TestSlackDriver_Type(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeSlack, driver.Type())
}

func TestSlackDriver_Cleanup(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}
	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}

func TestSlackDriver_Revoke_NoOp(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{},
		},
	}
	// Slack bot tokens are static — revoke is a no-op
	err := driver.Revoke(context.Background(), "any-lease-id")
	assert.NoError(t, err)

	err = driver.Revoke(context.Background(), "")
	assert.NoError(t, err)
}

func TestSlackDriver_NotRotatable(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{},
		},
	}
	// SlackDriver should not implement Rotatable
	var sd credential.SourceDriver = driver
	_, ok := sd.(credential.Rotatable)
	assert.False(t, ok, "SlackDriver should not implement credential.Rotatable")
}

func TestSlackDriver_MintCredential(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{"api_url": "https://slack.com/api"},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-slack",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"api_key": "xoxb-test-token-123",
		},
	}

	rawData, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "xoxb-test-token-123", rawData["api_key"])
	assert.Equal(t, time.Duration(0), ttl)
	assert.Equal(t, "", leaseID)
}

func TestSlackDriver_MintCredential_EmptyKey(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{},
		},
	}

	spec := &credential.CredSpec{
		Name: "test-slack",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"api_key": "",
		},
	}

	_, _, _, err := driver.MintCredential(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Slack bot token configured")
}

func TestSlackDriver_VerifySpec(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/auth.test", r.URL.Path)
		assert.Equal(t, "Bearer xoxb-valid-token", r.Header.Get("Authorization"))

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true,"url":"https://test.slack.com/","team":"Test","user":"bot"}`))
	}))
	defer server.Close()

	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{"api_url": server.URL},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-verify",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"api_key": "xoxb-valid-token",
		},
	}

	err := driver.VerifySpec(context.Background(), spec)
	assert.NoError(t, err)
}

func TestSlackDriver_VerifySpec_InvalidKey(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer server.Close()

	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{"api_url": server.URL},
		},
		httpClient: server.Client(),
	}

	spec := &credential.CredSpec{
		Name: "test-verify",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"api_key": "xoxb-invalid-token",
		},
	}

	err := driver.VerifySpec(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestSlackDriver_VerifySpec_EmptyKey(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{},
		},
		httpClient: &http.Client{},
	}

	spec := &credential.CredSpec{
		Name: "test-verify",
		Type: credential.TypeAPIKey,
		Config: map[string]string{
			"api_key": "",
		},
	}

	err := driver.VerifySpec(context.Background(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Slack bot token configured")
}

func TestSlackDriver_GetAPIURL(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{"api_url": "https://slack.com/api/"},
		},
	}
	// getAPIURL trims trailing slash
	assert.Equal(t, "https://slack.com/api", driver.getAPIURL())
}

func TestSlackDriver_GetAPIURL_Default(t *testing.T) {
	driver := &SlackDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeSlack,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, DefaultSlackAPIURL, driver.getAPIURL())
}

func TestValidateSlackURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
		errMsg  string
	}{
		{"https://slack.com/api", false, ""},
		{"https://slack.example.com", false, ""},
		{"http://slack.com/api", true, "must use https://"},
		{"ftp://slack.com/api", true, "must use https://"},
		{"https://", true, "must include a host"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateSlackURL(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
