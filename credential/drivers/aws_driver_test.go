package drivers

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSDriverFactory_Type(t *testing.T) {
	factory := &AWSDriverFactory{}
	assert.Equal(t, credential.SourceTypeAWS, factory.Type())
}

func TestAWSDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &AWSDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Contains(t, fields, "secret_access_key")
}

func TestAWSDriverFactory_ValidateConfig(t *testing.T) {
	factory := &AWSDriverFactory{}

	tests := []struct {
		name    string
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "valid config with assume_role_arn",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
				"assume_role_arn":   "arn:aws:iam::123456789012:role/test-role",
				"external_id":       "ext-123",
				"session_name":      "my-session",
				"session_duration":  "2h",
			},
			wantErr: false,
		},
		{
			name: "missing access_key_id",
			config: map[string]string{
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
			},
			wantErr: true,
			errMsg:  "access_key_id",
		},
		{
			name: "missing secret_access_key",
			config: map[string]string{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				"region":        "us-east-1",
			},
			wantErr: true,
			errMsg:  "secret_access_key",
		},
		{
			name: "missing region",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantErr: true,
			errMsg:  "region",
		},
		{
			name: "invalid session_duration",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
				"session_duration":  "invalid",
			},
			wantErr: true,
			errMsg:  "session_duration",
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

func TestAWSDriver_Type(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeAWS, driver.Type())
}

func TestAWSDriver_Cleanup(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: map[string]string{},
		},
	}
	err := driver.Cleanup(nil)
	assert.NoError(t, err)
}

func TestAWSDriver_Revoke_STS(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: map[string]string{},
		},
	}

	// STS credentials can't be revoked — should return nil
	err := driver.Revoke(nil, "sts:ASIA1234567890ABCDEF")
	assert.NoError(t, err)

	// Empty lease ID — should return nil
	err = driver.Revoke(nil, "")
	assert.NoError(t, err)
}

func TestAWSDriver_SupportsRotation(t *testing.T) {
	tests := []struct {
		name       string
		accessKey  string
		wantResult bool
	}{
		{
			name:       "permanent IAM key supports rotation",
			accessKey:  "AKIAIOSFODNN7EXAMPLE",
			wantResult: true,
		},
		{
			name:       "STS temporary key does not support rotation",
			accessKey:  "ASIAIOSFODNN7EXAMPLE",
			wantResult: false,
		},
		{
			name:       "empty key does not support rotation",
			accessKey:  "",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &AWSDriver{
				credSource: &credential.CredSource{
					Type: credential.SourceTypeAWS,
					Config: map[string]string{
						"access_key_id": tt.accessKey,
					},
				},
			}
			assert.Equal(t, tt.wantResult, driver.SupportsRotation())
		})
	}
}

func TestApplyKeyMap(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		keyMap   string
		expected map[string]interface{}
	}{
		{
			name: "basic remapping",
			data: map[string]interface{}{
				"accessKeyId": "AKIA123",
				"secretKey":   "secret123",
			},
			keyMap: "accessKeyId=access_key_id,secretKey=secret_access_key",
			expected: map[string]interface{}{
				"access_key_id":     "AKIA123",
				"secret_access_key": "secret123",
			},
		},
		{
			name: "missing source key",
			data: map[string]interface{}{
				"accessKeyId": "AKIA123",
			},
			keyMap: "accessKeyId=access_key_id,missing=other",
			expected: map[string]interface{}{
				"access_key_id": "AKIA123",
			},
		},
		{
			name: "whitespace handling",
			data: map[string]interface{}{
				"key1": "val1",
			},
			keyMap: " key1 = mapped_key1 ",
			expected: map[string]interface{}{
				"mapped_key1": "val1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyKeyMap(tt.data, tt.keyMap)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAWSDriver_MintCredential_InvalidMethod(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAWS,
			Config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			},
		},
		region: "us-east-1",
	}
	// Build clients so authenticate doesn't fail (no assume_role_arn)
	driver.buildClients(driver.baseCreds)
	driver.baseCredsVerified = true

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeAWSAccessKeys,
		Config: map[string]string{
			"mint_method": "invalid",
		},
	}

	_, _, _, err := driver.MintCredential(nil, spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}
