package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthBearerTokenCredType_Metadata(t *testing.T) {
	ct := NewOAuthBearerTokenCredType()
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeOAuthBearerToken, metadata.Name)
	assert.Equal(t, credential.CategoryOAuth, metadata.Category)
	assert.Contains(t, metadata.Description, "OAuth2 bearer token")
	assert.Equal(t, 1*time.Hour, metadata.DefaultTTL)
}

func TestOAuthBearerTokenCredType_ValidateConfig(t *testing.T) {
	ct := NewOAuthBearerTokenCredType()

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "oauth2 source - empty config (scope optional)",
			config:     map[string]string{},
			sourceType: credential.SourceTypeOAuth2,
			wantErr:    false,
		},
		{
			name:       "oauth2 source - with scope",
			config:     map[string]string{"scope": "read write"},
			sourceType: credential.SourceTypeOAuth2,
			wantErr:    false,
		},
		{
			name:       "unsupported source type - local",
			config:     map[string]string{},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "require an oauth2 or vault source",
		},
		{
			name:       "unsupported source type - aws",
			config:     map[string]string{},
			sourceType: credential.SourceTypeAWS,
			wantErr:    true,
			errMsg:     "require an oauth2 or vault source",
		},
		{
			name:       "unsupported source type - static apikey",
			config:     map[string]string{},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    true,
			errMsg:     "require an oauth2 or vault source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.ValidateConfig(tt.config, tt.sourceType)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOAuthBearerTokenCredType_Parse(t *testing.T) {
	ct := NewOAuthBearerTokenCredType()

	tests := []struct {
		name     string
		rawData  map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid api_key field",
			rawData: map[string]interface{}{
				"api_key": "eyJhbGciOiJSUzI1NiJ9.test-token",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name: "valid access_token alternative field",
			rawData: map[string]interface{}{
				"access_token": "eyJhbGciOiJSUzI1NiJ9.test-token",
			},
			leaseTTL: 30 * time.Minute,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name: "valid with optional fields",
			rawData: map[string]interface{}{
				"api_key":    "test-token",
				"scope":      "read write",
				"token_type": "Bearer",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name:     "missing token",
			rawData:  map[string]interface{}{},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid api_key",
		},
		{
			name: "empty token",
			rawData: map[string]interface{}{
				"api_key": "",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid api_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := ct.Parse(tt.rawData, tt.leaseTTL, tt.leaseID)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cred)
				assert.Equal(t, credential.TypeOAuthBearerToken, cred.Type)
				assert.Equal(t, credential.CategoryOAuth, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.NotEmpty(t, cred.Data["api_key"])
				// OAuth tokens are not revocable
				assert.False(t, cred.Revocable)
			}
		})
	}
}

func TestOAuthBearerTokenCredType_Parse_OptionalFields(t *testing.T) {
	ct := NewOAuthBearerTokenCredType()

	rawData := map[string]interface{}{
		"api_key":    "test-token",
		"scope":      "read write",
		"token_type": "Bearer",
	}

	cred, err := ct.Parse(rawData, 1*time.Hour, "")
	require.NoError(t, err)

	assert.Equal(t, "test-token", cred.Data["api_key"])
	assert.Equal(t, "read write", cred.Data["scope"])
	assert.Equal(t, "Bearer", cred.Data["token_type"])
}

func TestOAuthBearerTokenCredType_Validate(t *testing.T) {
	ct := NewOAuthBearerTokenCredType()

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeOAuthBearerToken,
				Data: map[string]string{
					"api_key": "test-token",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{
					"api_key": "test-token",
				},
			},
			wantErr: true,
			errMsg:  "expected type oauth_bearer_token",
		},
		{
			name: "missing api_key",
			cred: &credential.Credential{
				Type: credential.TypeOAuthBearerToken,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing api_key",
		},
		{
			name: "empty api_key",
			cred: &credential.Credential{
				Type: credential.TypeOAuthBearerToken,
				Data: map[string]string{
					"api_key": "",
				},
			},
			wantErr: true,
			errMsg:  "missing api_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ct.Validate(tt.cred)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOAuthBearerTokenCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewOAuthBearerTokenCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestOAuthBearerTokenCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewOAuthBearerTokenCredType()
	assert.Nil(t, ct.SensitiveConfigFields())
}

func TestOAuthBearerTokenCredType_FieldSchemas(t *testing.T) {
	ct := NewOAuthBearerTokenCredType()
	schemas := ct.FieldSchemas()

	assert.Contains(t, schemas, "api_key")
	assert.True(t, schemas["api_key"].Sensitive)
	assert.NotEmpty(t, schemas["api_key"].Description)

	assert.Contains(t, schemas, "scope")
	assert.False(t, schemas["scope"].Sensitive)

	assert.Contains(t, schemas, "token_type")
	assert.False(t, schemas["token_type"].Sensitive)
}
