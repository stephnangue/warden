package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyCredType_Metadata(t *testing.T) {
	ct := NewAPIKeyCredType()
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeAPIKey, metadata.Name)
	assert.Equal(t, credential.CategoryAPI, metadata.Category)
	assert.Contains(t, metadata.Description, "API key")
	assert.Equal(t, time.Duration(0), metadata.DefaultTTL)
}

func TestAPIKeyCredType_ValidateConfig(t *testing.T) {
	ct := NewAPIKeyCredType()

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		// --- apikey source ---
		{
			name: "apikey source - valid config",
			config: map[string]string{
				"api_key": "sk-xxxxxxxxxxxxxxxxxxxx",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    false,
		},
		{
			name: "apikey source - with organization_id",
			config: map[string]string{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"organization_id": "org-123",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    false,
		},
		{
			name: "apikey source - with organization_id and project_id",
			config: map[string]string{
				"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
				"organization_id": "org-123",
				"project_id":      "proj-456",
			},
			sourceType: credential.SourceTypeAPIKey,
			wantErr:    false,
		},
		{
			name:       "apikey source - missing api_key",
			config:     map[string]string{},
			sourceType: credential.SourceTypeAPIKey,
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
			errMsg:     "require an apikey, local, or vault source",
		},
		// --- Vault source ---
		{
			name: "vault source - valid static_apikey config",
			config: map[string]string{
				"mint_method": "static_apikey",
				"kv2_mount":   "secret",
				"secret_path": "apikeys/my-service",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name: "vault source - missing mint_method",
			config: map[string]string{
				"kv2_mount":   "secret",
				"secret_path": "apikeys/my-service",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'mint_method' must be 'static_apikey'",
		},
		{
			name: "vault source - missing kv2_mount",
			config: map[string]string{
				"mint_method": "static_apikey",
				"secret_path": "apikeys/my-service",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'kv2_mount' is required",
		},
		{
			name: "vault source - missing secret_path",
			config: map[string]string{
				"mint_method": "static_apikey",
				"kv2_mount":   "secret",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'secret_path' is required",
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

func TestAPIKeyCredType_Parse(t *testing.T) {
	ct := NewAPIKeyCredType()

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
				assert.Equal(t, credential.TypeAPIKey, cred.Type)
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

func TestAPIKeyCredType_Parse_OptionalFields(t *testing.T) {
	ct := NewAPIKeyCredType()

	rawData := map[string]interface{}{
		"api_key":         "sk-xxxxxxxxxxxxxxxxxxxx",
		"key_id":          "key-123",
		"key_name":        "production-key",
		"organization_id": "org-456",
		"project_id":      "proj-789",
	}

	cred, err := ct.Parse(rawData, 0, "")
	require.NoError(t, err)

	assert.Equal(t, "sk-xxxxxxxxxxxxxxxxxxxx", cred.Data["api_key"])
	assert.Equal(t, "key-123", cred.Data["key_id"])
	assert.Equal(t, "production-key", cred.Data["key_name"])
	assert.Equal(t, "org-456", cred.Data["organization_id"])
	assert.Equal(t, "proj-789", cred.Data["project_id"])
}

func TestAPIKeyCredType_Validate(t *testing.T) {
	ct := NewAPIKeyCredType()

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
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
			errMsg:  "expected type api_key",
		},
		{
			name: "missing api_key",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing api_key",
		},
		{
			name: "empty api_key",
			cred: &credential.Credential{
				Type: credential.TypeAPIKey,
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

func TestAPIKeyCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewAPIKeyCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestAPIKeyCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewAPIKeyCredType()
	fields := ct.SensitiveConfigFields()
	assert.Len(t, fields, 1)
	assert.Contains(t, fields, "api_key")
}

func TestAPIKeyCredType_FieldSchemas(t *testing.T) {
	ct := NewAPIKeyCredType()
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

	assert.Contains(t, schemas, "project_id")
	assert.False(t, schemas["project_id"].Sensitive)
}
