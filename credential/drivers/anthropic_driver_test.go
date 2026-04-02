package drivers

import (
	"context"
	"io"
	"testing"
	"time"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDriverLogger() *logger.GatedLogger {
	config := &logger.Config{
		Level:   logger.ErrorLevel,
		Format:  logger.JSONFormat,
		Outputs: []io.Writer{io.Discard},
	}
	gateConfig := logger.GatedWriterConfig{
		Underlying: io.Discard,
	}
	gl, _ := logger.NewGatedLogger(config, gateConfig)
	return gl
}

// =============================================================================
// AnthropicDriver Tests
// =============================================================================

func TestAnthropicDriverFactory_Type(t *testing.T) {
	f := &AnthropicDriverFactory{}
	assert.Equal(t, credential.SourceTypeAnthropic, f.Type())
}

func TestAnthropicDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &AnthropicDriverFactory{}
	assert.Nil(t, f.SensitiveConfigFields())
}

func TestAnthropicDriverFactory_ValidateConfig(t *testing.T) {
	f := &AnthropicDriverFactory{}

	// Valid config (api_url is optional)
	err := f.ValidateConfig(map[string]string{})
	assert.NoError(t, err)

	// Valid with api_url
	err = f.ValidateConfig(map[string]string{
		"api_url": "https://api.anthropic.com",
	})
	assert.NoError(t, err)

	// Invalid api_url (not https)
	err = f.ValidateConfig(map[string]string{
		"api_url": "http://api.anthropic.com",
	})
	assert.Error(t, err)
}

func TestAnthropicDriverFactory_Create(t *testing.T) {
	f := &AnthropicDriverFactory{}
	driver, err := f.Create(map[string]string{}, testDriverLogger())
	require.NoError(t, err)
	require.NotNil(t, driver)
	assert.Equal(t, credential.SourceTypeAnthropic, driver.Type())
}

func TestAnthropicDriver_MintCredential(t *testing.T) {
	f := &AnthropicDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())

	t.Run("missing api_key", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name:   "test",
			Config: map[string]string{},
		}
		_, _, _, err := driver.MintCredential(context.Background(), spec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no Anthropic API key")
	})

	t.Run("with api_key", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test",
			Config: map[string]string{
				"api_key": "sk-ant-test123",
			},
		}
		data, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Equal(t, "sk-ant-test123", data["api_key"])
		assert.Equal(t, time.Duration(0), ttl)
		assert.Empty(t, leaseID)
	})

	t.Run("with organization_id", func(t *testing.T) {
		spec := &credential.CredSpec{
			Name: "test",
			Config: map[string]string{
				"api_key":         "sk-ant-test123",
				"organization_id": "org-123",
			},
		}
		data, _, _, err := driver.MintCredential(context.Background(), spec)
		require.NoError(t, err)
		assert.Equal(t, "org-123", data["organization_id"])
	})
}

func TestAnthropicDriver_Revoke(t *testing.T) {
	f := &AnthropicDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())

	// Revoke is a no-op
	err := driver.Revoke(context.Background(), "lease-123")
	assert.NoError(t, err)
}

func TestAnthropicDriver_Cleanup(t *testing.T) {
	f := &AnthropicDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())

	err := driver.Cleanup(context.Background())
	assert.NoError(t, err)
}

func TestAnthropicDriver_GetAPIURL(t *testing.T) {
	f := &AnthropicDriverFactory{}

	t.Run("default URL", func(t *testing.T) {
		driver, _ := f.Create(map[string]string{}, testDriverLogger())
		d := driver.(*AnthropicDriver)
		assert.Equal(t, DefaultAnthropicAPIURL, d.getAPIURL())
	})

	t.Run("custom URL", func(t *testing.T) {
		driver, _ := f.Create(map[string]string{
			"api_url": "https://custom.api.com/",
		}, testDriverLogger())
		d := driver.(*AnthropicDriver)
		assert.Equal(t, "https://custom.api.com", d.getAPIURL())
	})
}

func TestAnthropicDriver_VerifySpec_MissingKey(t *testing.T) {
	f := &AnthropicDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())

	spec := &credential.CredSpec{
		Name:   "test",
		Config: map[string]string{},
	}
	err := driver.(*AnthropicDriver).VerifySpec(context.Background(), spec)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no Anthropic API key")
}

func TestValidateAnthropicURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://api.anthropic.com", false},
		{"https://custom.example.com", false},
		{"http://api.anthropic.com", true},
		{"not-a-url", true},
		{"https://", true},
	}
	for _, tc := range tests {
		err := validateAnthropicURL(tc.url)
		if tc.wantErr {
			assert.Error(t, err, "url=%s", tc.url)
		} else {
			assert.NoError(t, err, "url=%s", tc.url)
		}
	}
}

// =============================================================================
// LocalDriver Tests
// =============================================================================

func TestLocalDriverFactory_Type(t *testing.T) {
	f := &LocalDriverFactory{}
	assert.Equal(t, credential.SourceTypeLocal, f.Type())
}

func TestLocalDriverFactory_ValidateConfig(t *testing.T) {
	f := &LocalDriverFactory{}
	assert.NoError(t, f.ValidateConfig(map[string]string{}))
}

func TestLocalDriverFactory_SensitiveConfigFields(t *testing.T) {
	f := &LocalDriverFactory{}
	assert.Empty(t, f.SensitiveConfigFields())
}

func TestLocalDriverFactory_Create(t *testing.T) {
	f := &LocalDriverFactory{}
	driver, err := f.Create(map[string]string{}, testDriverLogger())
	require.NoError(t, err)
	assert.Equal(t, credential.SourceTypeLocal, driver.Type())
}

func TestLocalDriver_MintCredential(t *testing.T) {
	f := &LocalDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())

	spec := &credential.CredSpec{
		Name: "test",
		Config: map[string]string{
			"username": "admin",
			"password": "secret",
		},
	}

	data, ttl, leaseID, err := driver.MintCredential(context.Background(), spec)
	require.NoError(t, err)
	assert.Equal(t, "admin", data["username"])
	assert.Equal(t, "secret", data["password"])
	assert.Equal(t, time.Duration(0), ttl)
	assert.Empty(t, leaseID)
}

func TestLocalDriver_Revoke(t *testing.T) {
	f := &LocalDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())
	assert.NoError(t, driver.Revoke(context.Background(), "lease"))
}

func TestLocalDriver_Cleanup(t *testing.T) {
	f := &LocalDriverFactory{}
	driver, _ := f.Create(map[string]string{}, testDriverLogger())
	assert.NoError(t, driver.Cleanup(context.Background()))
}

// =============================================================================
// RegisterBuiltinDrivers Tests
// =============================================================================

