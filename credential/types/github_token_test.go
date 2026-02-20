package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestPEM generates a PEM-encoded RSA private key for testing
func generateTestPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	return string(pem.EncodeToMemory(block))
}

func TestGitHubTokenCredType_Metadata(t *testing.T) {
	ct := NewGitHubTokenCredType()
	metadata := ct.Metadata()

	assert.Equal(t, credential.TypeGitHubToken, metadata.Name)
	assert.Equal(t, credential.CategoryAPI, metadata.Category)
	assert.Contains(t, metadata.Description, "GitHub token")
	assert.Equal(t, time.Duration(0), metadata.DefaultTTL)
}

func TestGitHubTokenCredType_ValidateConfig(t *testing.T) {
	ct := NewGitHubTokenCredType()

	testPEM := generateTestPEM(t)

	tests := []struct {
		name       string
		config     map[string]string
		sourceType string
		wantErr    bool
		errMsg     string
	}{
		// --- GitHub source: app mode ---
		{
			name: "github app - valid config",
			config: map[string]string{
				"auth_method":     "app",
				"app_id":          "12345",
				"private_key":     testPEM,
				"installation_id": "67890",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    false,
		},
		{
			name: "github app - missing app_id",
			config: map[string]string{
				"auth_method":     "app",
				"private_key":     testPEM,
				"installation_id": "67890",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "app_id",
		},
		{
			name: "github app - missing private_key",
			config: map[string]string{
				"auth_method":     "app",
				"app_id":          "12345",
				"installation_id": "67890",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "private_key",
		},
		{
			name: "github app - missing installation_id",
			config: map[string]string{
				"auth_method": "app",
				"app_id":      "12345",
				"private_key": testPEM,
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "installation_id",
		},
		{
			name: "github app - invalid PEM",
			config: map[string]string{
				"auth_method":     "app",
				"app_id":          "12345",
				"private_key":     "not-a-pem",
				"installation_id": "67890",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "must be valid PEM format",
		},
		// --- GitHub source: pat mode ---
		{
			name: "github pat - valid config",
			config: map[string]string{
				"auth_method": "pat",
				"token":       "ghp_xxxxxxx",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    false,
		},
		{
			name: "github pat - missing token",
			config: map[string]string{
				"auth_method": "pat",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "token",
		},
		// --- GitHub source: auth_method validation ---
		{
			name:       "github - missing auth_method",
			config:     map[string]string{},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "auth_method",
		},
		{
			name: "github - unsupported auth_method",
			config: map[string]string{
				"auth_method": "oauth",
			},
			sourceType: credential.SourceTypeGitHub,
			wantErr:    true,
			errMsg:     "must be one of: app, pat",
		},
		// --- Local source ---
		{
			name: "local source - valid config",
			config: map[string]string{
				"token": "ghp_xxxxxxx",
			},
			sourceType: credential.SourceTypeLocal,
			wantErr:    false,
		},
		{
			name:       "local source - missing token",
			config:     map[string]string{},
			sourceType: credential.SourceTypeLocal,
			wantErr:    true,
			errMsg:     "token",
		},
		// --- Unsupported source types ---
		{
			name: "unsupported source type",
			config: map[string]string{
				"token": "test",
			},
			sourceType: "aws",
			wantErr:    true,
			errMsg:     "require a github or local source",
		},
		{
			name: "unsupported source type - vault",
			config: map[string]string{
				"token": "test",
			},
			sourceType: credential.SourceTypeVault,
			wantErr:    true,
			errMsg:     "require a github or local source",
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

func TestGitHubTokenCredType_Parse(t *testing.T) {
	ct := NewGitHubTokenCredType()

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
				"token":       "ghs_installation_token_123",
				"expires_at":  "2026-02-15T12:00:00Z",
				"permissions": `{"contents":"read","metadata":"read"}`,
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name: "valid PAT token (minimal)",
			rawData: map[string]interface{}{
				"token": "ghp_pat_token",
			},
			leaseTTL: 0,
			leaseID:  "",
			wantErr:  false,
		},
		{
			name:     "missing token",
			rawData:  map[string]interface{}{},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid token",
		},
		{
			name: "empty token",
			rawData: map[string]interface{}{
				"token": "",
			},
			leaseTTL: 1 * time.Hour,
			leaseID:  "",
			wantErr:  true,
			errMsg:   "missing or invalid token",
		},
		{
			name: "token with lease",
			rawData: map[string]interface{}{
				"token": "ghs_leased",
			},
			leaseTTL: 30 * time.Minute,
			leaseID:  "lease-abc",
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
				assert.Equal(t, credential.TypeGitHubToken, cred.Type)
				assert.Equal(t, credential.CategoryAPI, cred.Category)
				assert.Equal(t, tt.leaseTTL, cred.LeaseTTL)
				assert.Equal(t, tt.leaseID, cred.LeaseID)
				assert.NotEmpty(t, cred.Data["token"])
				if tt.leaseID != "" {
					assert.True(t, cred.Revocable)
				} else {
					assert.False(t, cred.Revocable)
				}
			}
		})
	}
}

func TestGitHubTokenCredType_Parse_OptionalFields(t *testing.T) {
	ct := NewGitHubTokenCredType()

	rawData := map[string]interface{}{
		"token":       "ghs_test",
		"expires_at":  "2026-02-15T12:00:00Z",
		"permissions": `{"contents":"read"}`,
	}

	cred, err := ct.Parse(rawData, 1*time.Hour, "")
	require.NoError(t, err)

	assert.Equal(t, "ghs_test", cred.Data["token"])
	assert.Equal(t, "2026-02-15T12:00:00Z", cred.Data["expires_at"])
	assert.Equal(t, `{"contents":"read"}`, cred.Data["permissions"])
}

func TestGitHubTokenCredType_Validate(t *testing.T) {
	ct := NewGitHubTokenCredType()

	tests := []struct {
		name    string
		cred    *credential.Credential
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid credential",
			cred: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{
					"token": "ghp_xxxxxxx",
				},
			},
			wantErr: false,
		},
		{
			name: "wrong type",
			cred: &credential.Credential{
				Type: credential.TypeVaultToken,
				Data: map[string]string{
					"token": "ghp_xxxxxxx",
				},
			},
			wantErr: true,
			errMsg:  "expected type github_token",
		},
		{
			name: "missing token",
			cred: &credential.Credential{
				Type: credential.TypeGitHubToken,
				Data: map[string]string{},
			},
			wantErr: true,
			errMsg:  "missing token",
		},
		{
			name: "empty token",
			cred: &credential.Credential{
				Type: credential.TypeGitHubToken,
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

func TestGitHubTokenCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewGitHubTokenCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestGitHubTokenCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewGitHubTokenCredType()
	fields := ct.SensitiveConfigFields()
	assert.Len(t, fields, 2)
	assert.Contains(t, fields, "token")
	assert.Contains(t, fields, "private_key")
}

func TestGitHubTokenCredType_FieldSchemas(t *testing.T) {
	ct := NewGitHubTokenCredType()
	schemas := ct.FieldSchemas()

	assert.Contains(t, schemas, "token")
	assert.True(t, schemas["token"].Sensitive)
	assert.NotEmpty(t, schemas["token"].Description)

	assert.Contains(t, schemas, "expires_at")
	assert.False(t, schemas["expires_at"].Sensitive)

	assert.Contains(t, schemas, "permissions")
	assert.False(t, schemas["permissions"].Sensitive)
}
