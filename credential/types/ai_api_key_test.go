package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAIAPIKeyCredType_Metadata(t *testing.T) {
	ct := NewAIAPIKeyCredType()
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeAIAPIKey, metadata.Name)
	assert.Equal(t, credential.CategoryAPI, metadata.Category)
	assert.Contains(t, metadata.Description, "AI provider")
	assert.Equal(t, time.Duration(0), metadata.DefaultTTL)
}

func TestAIAPIKeyCredType_ValidateConfig(t *testing.T) {
	ct := NewAIAPIKeyCredType()

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		// --- Mistral source ---
		{
			name: "mistral source - valid config",
			config: map[string]string{
				"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
			},
			sourceType: credential.SourceTypeMistral,
			wantErr:    false,
		},
		{
			name: "mistral source - with organization_id",
			config: map[string]string{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"organization_id": "org-123",
			},
			sourceType: credential.SourceTypeMistral,
			wantErr:    false,
		},
		{
			name:       "mistral source - missing api_key",
			config:     map[string]string{},
			sourceType: credential.SourceTypeMistral,
			wantErr:    true,
			errMsg:     "api_key",
		},
		// --- Local source ---
		{
			name: "local source - valid config",
			config: map[string]string{
				"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    false,
		},
		{
			name: "local source - with optional fields",
			config: map[string]string{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"organization_id": "org-123",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    false,
		},
		{
			name:       "local source - missing api_key",
			config:     map[string]string{},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "api_key",
		},
		{
			name: "local source - empty api_key",
			config: map[string]string{
				"api_key": "",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "api_key",
		},
		// --- Unsupported source types ---
		{
			name: "unsupported source type - aws",
			config: map[string]string{
				"api_key": "sk-test",
			},
			sourceType: "aws",
			wantErr:    true,
			errMsg:     "require a mistral or local source",
		},
		{
			name: "unsupported source type - vault",
			config: map[string]string{
				"api_key": "sk-test",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "require a mistral or local source",
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

func TestAIAPIKeyCredType_Parse(t *testing.T) {
	ct := NewAIAPIKeyCredType()

	tests := []struct {
		name     string
		rawData  map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid api_key",
			rawData: map[string]interface{}{
				"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name: "valid api_key with optional fields",
			rawData: map[string]interface{}{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"key_id":          "key-123",
				"key_name":        "production-key",
				"organization_id": "org-456",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name:     "missing api_key",
			rawData:  map[string]interface{}{},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid api_key",
		},
		{
			name: "empty api_key",
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
				assert.Equal(t, credential.TypeAIAPIKey, cred.Type)
				assert.Equal(t, credential.CategoryAPI, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				assert.NotEmpty(t, cred.Data["api_key"])
				// Static keys are never revocable
				assert.False(t, cred.Revocable)
			}
		})
	}
}

func TestAIAPIKeyCredType_Parse_OptionalFields(t *testing.T) {
	ct := NewAIAPIKeyCredType()

	rawData := map[string]interface{}{
		"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
		"key_id":          "key-123",
		"key_name":        "production-key",
		"organization_id": "org-456",
	}

	cred, err := ct.Parse(rawData, 0, "")
	require.NoError(t, err)

	assert.Equal(t, "sk-xxxxxxxxxxxxxxxxxxxx", cred.Data["api_key"])
	assert.Equal(t, "key-123", cred.Data["key_id"])
	assert.Equal(t, "production-key", cred.Data["key_name"])
	assert.Equal(t, "org-456", cred.Data["organization_id"])
}

func TestAIAPIKeyCredType_Validate(t *testing.T) {
	ct := NewAIAPIKeyCredType()

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeAIAPIKey,
				Data: map[string]string{
					"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
				},
			},
			wantErr: true,
			errMsg:  "expected type ai_api_key",
		},
		{
			name: "missing api_key",
			cred: &credential.Credential{
				Type: credential.TypeAIAPIKey,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing api_key",
		},
		{
			name: "empty api_key",
			cred: &credential.Credential{
				Type: credential.TypeAIAPIKey,
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

func TestAIAPIKeyCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewAIAPIKeyCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestAIAPIKeyCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewAIAPIKeyCredType()
	fields := ct.SensitiveConfigFields()
	assert.Len(t, fields, 1)
	assert.Contains(t, fields, "api_key")
}

func TestAIAPIKeyCredType_FieldSchemas(t *testing.T) {
	ct := NewAIAPIKeyCredType()
	schemas := ct.FieldSchemas()

	assert.Contains(t, schemas, "api_key")
	assert.True(t, schemas["api_key"].Sensitive)
	assert.NotEmpty(t, schemas["api_key"].Description)

	assert.Contains(t, schemas, "key_id")
	assert.False(t, schemas["key_id"].Sensitive)

	assert.Contains(t, schemas, "key_name")
	assert.False(t, schemas["key_name"].Sensitive)

	assert.Contains(t, schemas, "organization_id")
	assert.False(t, schemas["organization_id"].Sensitive)
}
