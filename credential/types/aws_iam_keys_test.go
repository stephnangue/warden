package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
)

func TestAWSIAMAccessKeysCredType_Metadata(t *testing.T) {
	ct := &AWSIAMAccessKeysCredType{}
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeAWSAccessKeys, metadata.Name)
	assert.Equal(t, credential.CategoryCloudIAM, metadata.Category)
	assert.Equal(t, "AWS IAM access keys (static and STS temporary credentials)", metadata.Description)
	assert.Equal(t, 12*time.Hour, metadata.DefaultTTL)
}

func TestAWSIAMAccessKeysCredType_ValidateConfig_LocalSource(t *testing.T) {
	ct := &AWSIAMAccessKeysCredType{}

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid local config",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    false,
		},
		{
			name: "missing access_key_id",
			config: map[string]string{
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "access_key_id",
		},
		{
			name: "missing secret_access_key",
			config: map[string]string{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "secret_access_key",
		},
		{
			name:       "empty config",
			config:     map[string]string{},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
		},
		{
			name: "invalid field in local config",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
				"aws_mount":         "aws", // not allowed in local
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "invalid config field",
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

func TestAWSIAMAccessKeysCredType_ValidateConfig_VaultSource(t *testing.T) {
	ct := &AWSIAMAccessKeysCredType{}

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid dynamic_aws config",
			config: map[string]string{
				"mint_method": "dynamic_aws",
				"aws_mount":   "aws",
				"role_name":   "my-role",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name: "valid kv2_static config",
			config: map[string]string{
				"mint_method": "kv2_static",
				"kv2_mount":   "secret",
				"secret_path": "aws-creds/myapp",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    false,
		},
		{
			name:       "missing mint_method",
			config:     map[string]string{},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "'mint_method' is required",
		},
		{
			name: "unsupported mint_method",
			config: map[string]string{
				"mint_method": "invalid",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "unsupported mint_method",
		},
		{
			name: "dynamic_aws without role_name",
			config: map[string]string{
				"mint_method": "dynamic_aws",
				"aws_mount":   "aws",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "role_name",
		},
		{
			name: "kv2_static without secret_path",
			config: map[string]string{
				"mint_method": "kv2_static",
				"kv2_mount":   "secret",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "secret_path",
		},
		{
			name: "unsupported source type",
			config: map[string]string{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
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

func TestAWSIAMAccessKeysCredType_Parse(t *testing.T) {
	ct := &AWSIAMAccessKeysCredType{}

	tests := []struct {
		name               string
		rawData            map[string]interface{}
		leaseTTL           time.Duration
		leaseID            string
		wantErr            bool
		errMsg             string
		expectedRevocable  bool
		checkSessionToken  bool
		checkSecurityToken bool
	}{
		{
			name: "valid IAM credentials",
			rawData: map[string]interface{}{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
			},
			leaseTTL:          0,
			leaseID:           "",
			wantErr:           false,
			expectedRevocable: false,
		},
		{
			name: "valid STS temporary credentials",
			rawData: map[string]interface{}{
				"access_key_id":     "ASIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
				"session_token":     "AQoDYXdzEJr...",
			},
			leaseTTL:          1 * time.Hour,
			leaseID:           "lease-123",
			wantErr:           false,
			expectedRevocable: true,
			checkSessionToken: true,
		},
		{
			name: "valid credentials with security_token",
			rawData: map[string]interface{}{
				"access_key_id":     "ASIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
				"security_token":    "FwoGZXIvYXdzEBY...",
			},
			leaseTTL:           1 * time.Hour,
			leaseID:            "lease-456",
			wantErr:            false,
			expectedRevocable:  true,
			checkSecurityToken: true,
		},
		{
			name: "Vault AWS engine field names (access_key/secret_key)",
			rawData: map[string]interface{}{
				"access_key": "AKIAIOSFODNN7EXAMPLE",
				"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
			},
			leaseTTL:          12 * time.Hour,
			leaseID:           "vault-lease-789",
			wantErr:           false,
			expectedRevocable: true,
		},
		{
			name:     "missing access_key_id",
			rawData:  map[string]interface{}{},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid access_key_id",
		},
		{
			name: "missing secret_access_key",
			rawData: map[string]interface{}{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid secret_access_key",
		},
		{
			name: "empty access_key_id",
			rawData: map[string]interface{}{
				"access_key_id":     "",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid access_key_id",
		},
		{
			name: "empty secret_access_key",
			rawData: map[string]interface{}{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid secret_access_key",
		},
		{
			name: "with cred_source",
			rawData: map[string]interface{}{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYEKEY",
				"cred_source":       "vault",
			},
			leaseTTL:          0,
			leaseID:           "",
			wantErr:           false,
			expectedRevocable: false,
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
				assert.Equal(t, credential.TypeAWSAccessKeys, cred.Type)
				assert.Equal(t, credential.CategoryCloudIAM, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				assert.Equal(t, tt.expectedRevocable, cred.Revocable)
				assert.NotEmpty(t, cred.Data["access_key_id"])
				assert.NotEmpty(t, cred.Data["secret_access_key"])

				if tt.checkSessionToken {
					assert.NotEmpty(t, cred.Data["session_token"])
				}
				if tt.checkSecurityToken {
					assert.NotEmpty(t, cred.Data["security_token"])
				}
			}
		})
	}
}

func TestAWSIAMAccessKeysCredType_Validate(t *testing.T) {
	ct := &AWSIAMAccessKeysCredType{}

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid IAM user credential",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
			wantErr: false,
		},
		{
			name: "valid STS temporary credential",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id":     "ASIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					"session_token":     "AQoDYXdzEJr...",
				},
			},
			wantErr: false,
		},
		{
			name: "valid STS with security_token",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id":     "ASIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
					"security_token":    "FwoGZXIvYXdzEBY...",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
			wantErr: true,
			errMsg:  "expected type aws_access_keys",
		},
		{
			name: "missing access_key_id",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
			wantErr: true,
			errMsg:  "missing access_key_id",
		},
		{
			name: "empty access_key_id",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id":     "",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
			wantErr: true,
			errMsg:  "missing access_key_id",
		},
		{
			name: "invalid access_key_id prefix",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id":     "INVALIDPREFIX12345678",
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
			wantErr: true,
			errMsg:  "invalid access_key_id format",
		},
		{
			name: "missing secret_access_key",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				},
			},
			wantErr: true,
			errMsg:  "missing secret_access_key",
		},
		{
			name: "invalid secret_access_key length",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
					"secret_access_key": "too-short",
				},
			},
			wantErr: true,
			errMsg:  "invalid secret_access_key length",
		},
		{
			name: "STS credential missing session_token",
			cred: &credential.Credential{
				Type: credential.TypeAWSAccessKeys,
				Data: map[string]string{
					"access_key_id":     "ASIAIOSFODNN7EXAMPLE", // ASIA prefix = STS
					"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				},
			},
			wantErr: true,
			errMsg:  "STS temporary credentials require session_token or security_token",
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

func TestAWSIAMAccessKeysCredType_RequiresSpecRotation(t *testing.T) {
	ct := &AWSIAMAccessKeysCredType{}
	assert.False(t, ct.RequiresSpecRotation())
}

func TestAWSIAMAccessKeysCredType_FieldSchemas(t *testing.T) {
	ct := &AWSIAMAccessKeysCredType{}
	schemas := ct.FieldSchemas()

	// Check required fields exist
	assert.Contains(t, schemas, "access_key_id")
	assert.Contains(t, schemas, "secret_access_key")
	assert.Contains(t, schemas, "session_token")
	assert.Contains(t, schemas, "security_token")

	// Check sensitivity
	assert.False(t, schemas["access_key_id"].Sensitive)
	assert.True(t, schemas["secret_access_key"].Sensitive)
	assert.True(t, schemas["session_token"].Sensitive)
	assert.True(t, schemas["security_token"].Sensitive)

	// Check descriptions
	assert.NotEmpty(t, schemas["access_key_id"].Description)
	assert.NotEmpty(t, schemas["secret_access_key"].Description)
	assert.NotEmpty(t, schemas["session_token"].Description)
	assert.NotEmpty(t, schemas["security_token"].Description)
}

func TestAWSIAMAccessKeysCredType_Revoke_NoLeaseID(t *testing.T) {
	ct := &AWSIAMAccessKeysCredType{}

	// Credential without lease ID (static IAM credential)
	cred := &credential.Credential{
		Type:    credential.TypeAWSAccessKeys,
		LeaseID: "",
		Data: map[string]string{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		},
	}

	// Should return nil without calling driver (no lease to revoke)
	err := ct.Revoke(nil, cred, nil)
	assert.NoError(t, err)
}
