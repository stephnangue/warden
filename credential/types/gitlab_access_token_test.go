package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitLabAccessTokenCredType_Metadata(t *testing.T) {
	ct := NewGitLabAccessTokenCredType()
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeGitLabAccessToken, metadata.Name)
	assert.Equal(t, credential.CategoryAPI, metadata.Category)
	assert.Equal(t, "GitLab access token for API authentication", metadata.Description)
	assert.Equal(t, time.Duration(0), metadata.DefaultTTL)
}

func TestGitLabAccessTokenCredType_ValidateConfig(t *testing.T) {
	ct := NewGitLabAccessTokenCredType()

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		{
			name: "valid project_access_token config",
			config: map[string]string{
				"mint_method":  "project_access_token",
				"project_id":   "42",
				"token_name":   "warden-test",
				"scopes":       "api",
				"access_level": "30",
			},
			sourceType: credential.SourceTypeGitLab,
			wantErr:    false,
		},
		{
			name: "valid group_access_token config",
			config: map[string]string{
				"mint_method":  "group_access_token",
				"group_id":     "mygroup",
				"token_name":   "warden-test",
				"scopes":       "api,read_api",
				"access_level": "40",
			},
			sourceType: credential.SourceTypeGitLab,
			wantErr:    false,
		},
		{
			name:       "missing mint_method",
			config:     map[string]string{},
			sourceType: credential.SourceTypeGitLab,
			wantErr:    true,
			errMsg:     "'mint_method' is required",
		},
		{
			name: "unsupported mint_method",
			config: map[string]string{
				"mint_method": "personal_token",
			},
			sourceType: credential.SourceTypeGitLab,
			wantErr:    true,
			errMsg:     "must be one of:",
		},
		{
			name: "project_access_token missing project_id",
			config: map[string]string{
				"mint_method":  "project_access_token",
				"token_name":   "test",
				"scopes":       "api",
				"access_level": "30",
			},
			sourceType: credential.SourceTypeGitLab,
			wantErr:    true,
			errMsg:     "project_id",
		},
		{
			name: "project_access_token missing token_name",
			config: map[string]string{
				"mint_method":  "project_access_token",
				"project_id":   "42",
				"scopes":       "api",
				"access_level": "30",
			},
			sourceType: credential.SourceTypeGitLab,
			wantErr:    true,
			errMsg:     "token_name",
		},
		{
			name: "group_access_token missing group_id",
			config: map[string]string{
				"mint_method":  "group_access_token",
				"token_name":   "test",
				"scopes":       "api",
				"access_level": "30",
			},
			sourceType: credential.SourceTypeGitLab,
			wantErr:    true,
			errMsg:     "group_id",
		},
		{
			name: "unsupported source type",
			config: map[string]string{
				"token": "test",
			},
			sourceType: "aws",
			wantErr:    true,
			errMsg:     "require a gitlab source",
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

func TestGitLabAccessTokenCredType_Parse(t *testing.T) {
	ct := NewGitLabAccessTokenCredType()

	tests := []struct {
		name     string
		rawData  map[string]interface{}
		leaseTTL time.Duration
		leaseID  string
		wantErr  bool
		errMsg   string
	}{
		{
			name: "valid token with all fields",
			rawData: map[string]interface{}{
				"access_token": "glpat-xxxxxx",
				"token_id":     "42",
				"expires_at":   "2026-03-15",
				"scopes":       "api,read_api",
			},
			leaseTTL: 24 * time.Hour,
			leaseID:  "project_access_token:42:99",
			wantErr:  false,
		},
		{
			name: "valid token with minimal fields",
			rawData: map[string]interface{}{
				"access_token": "glpat-minimal",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  false,
		},
		{
			name:     "missing access_token",
			rawData:  map[string]interface{}{},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  true,
			errMsg:   "missing or invalid access_token",
		},
		{
			name: "empty access_token",
			rawData: map[string]interface{}{
				"access_token": "",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "lease-123",
			wantErr:  true,
			errMsg:   "missing or invalid access_token",
		},
		{
			name: "no lease (static token)",
			rawData: map[string]interface{}{
				"access_token": "glpat-static",
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
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cred)
				assert.Equal(t, credential.TypeGitLabAccessToken, cred.Type)
				assert.Equal(t, credential.CategoryAPI, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				assert.NotEmpty(t, cred.Data["access_token"])
				if tt.leaseID != "" {
					assert.True(t, cred.Revocable)
				} else {
					assert.False(t, cred.Revocable)
				}
			}
		})
	}
}

func TestGitLabAccessTokenCredType_Parse_OptionalFields(t *testing.T) {
	ct := NewGitLabAccessTokenCredType()

	rawData := map[string]interface{}{
		"access_token": "glpat-test",
		"token_id":     "42",
		"expires_at":   "2026-03-15",
		"scopes":       "api,read_api",
	}

	cred, err := ct.Parse(rawData, 24*time.Hour, "lease-1")
	require.NoError(t, err)

	assert.Equal(t, "glpat-test", cred.Data["access_token"])
	assert.Equal(t, "42", cred.Data["token_id"])
	assert.Equal(t, "2026-03-15", cred.Data["expires_at"])
	assert.Equal(t, "api,read_api", cred.Data["scopes"])
}

func TestGitLabAccessTokenCredType_Validate(t *testing.T) {
	ct := NewGitLabAccessTokenCredType()

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeGitLabAccessToken,
				Data: map[string]string{
					"access_token": "glpat-xxxxxx",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"access_token": "glpat-xxxxxx",
				},
			},
			wantErr: true,
			errMsg:  "expected type gitlab_access_token",
		},
		{
			name: "missing access_token",
			cred: &credential.Credential{
				Type: credential.TypeGitLabAccessToken,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing access_token",
		},
		{
			name: "empty access_token",
			cred: &credential.Credential{
				Type: credential.TypeGitLabAccessToken,
				Data: map[string]string{
					"access_token": "",
				},
			},
			wantErr: true,
			errMsg:  "missing access_token",
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

func TestGitLabAccessTokenCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewGitLabAccessTokenCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestGitLabAccessTokenCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewGitLabAccessTokenCredType()
	assert.Nil(t, ct.SensitiveConfigFields())
}

func TestGitLabAccessTokenCredType_FieldSchemas(t *testing.T) {
	ct := NewGitLabAccessTokenCredType()
	schemas := ct.FieldSchemas()

	assert.Contains(t, schemas, "access_token")
	assert.True(t, schemas["access_token"].Sensitive)
	assert.NotEmpty(t, schemas["access_token"].Description)

	assert.Contains(t, schemas, "token_id")
	assert.False(t, schemas["token_id"].Sensitive)

	assert.Contains(t, schemas, "expires_at")
	assert.False(t, schemas["expires_at"].Sensitive)

	assert.Contains(t, schemas, "scopes")
	assert.False(t, schemas["scopes"].Sensitive)
}
