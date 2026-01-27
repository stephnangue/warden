package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
)

func TestVaultTokenCredType_Metadata(t *testing.T) {
	ct := &VaultTokenCredType{}
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeVaultToken, metadata.Name)
	assert.Equal(t, credential.CategoryAPI, metadata.Category)
	assert.Equal(t, "HashiCorp Vault authentication token", metadata.Description)
	assert.Equal(t, 1*time.Hour, metadata.DefaultTTL)
}

func TestVaultTokenCredType_ValidateConfig_VaultSource(t *testing.T) {
	ct := &VaultTokenCredType{}

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid token_role config",
			config: map[string]string{
				"token_role": "my-role",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name:       "missing token_role",
			config:     map[string]string{},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'token_role' is required for dynamic Vault token generation",
		},
		{
			name: "unsupported source type",
			config: map[string]string{
				"token": "test-token",
			},
			sourceType: "unknown",
			wantErr:    true,
			errMsg:     "unsupported source type",
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

func TestVaultTokenCredType_Parse(t *testing.T) {
	ct := &VaultTokenCredType{}

	tests := []struct {
		name     string
		rawData  map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid token",
			rawData: map[string]interface{}{
				"token": "hvs.CAESIJlmkG2lL8xPqU...",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  false,
		},
		{
			name: "valid client_token (alternative field name)",
			rawData: map[string]interface{}{
				"client_token": "hvs.CAESIJlmkG2lL8xPqU...",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  false,
		},
		{
			name:     "missing token",
			rawData:  map[string]interface{}{},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  true,
			errMsg:   "missing or invalid token",
		},
		{
			name: "empty token",
			rawData: map[string]interface{}{
				"token": "",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  true,
			errMsg:   "missing or invalid token",
		},
		{
			name: "static token (zero TTL)",
			rawData: map[string]interface{}{
				"token": "hvs.static-token",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := ct.Parse(tt.rawData, tt.leaseTTL, tt.leaseID)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cred)
				assert.Equal(t, credential.TypeVaultToken, cred.Type)
				assert.Equal(t, credential.CategoryAPI, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				assert.NotEmpty(t, cred.Data["token"])
			}
		})
	}
}

func TestVaultTokenCredType_Validate(t *testing.T) {
	ct := &VaultTokenCredType{}

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"token": "hvs.CAESIJlmkG2lL8xPqU...",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"token": "hvs.CAESIJlmkG2lL8xPqU...",
				},
			},
			wantErr: true,
			errMsg:  "expected type vault_token",
		},
		{
			name: "missing token",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing token",
		},
		{
			name: "empty token",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"token": "",
				},
			},
			wantErr: true,
			errMsg:  "missing token",
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

func TestVaultTokenCredType_CanRotate(t *testing.T) {
	ct := &VaultTokenCredType{}
	assert.True(t, ct.CanRotate())
}

func TestVaultTokenCredType_FieldSchemas(t *testing.T) {
	ct := &VaultTokenCredType{}
	schemas := ct.FieldSchemas()

	assert.Contains(t, schemas, "token")
	assert.True(t, schemas["token"].Sensitive)
	assert.NotEmpty(t, schemas["token"].Description)
}
