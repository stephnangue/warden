package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// AzureBearerTokenCredType handles Azure AD Bearer tokens
type AzureBearerTokenCredType struct{}

// Metadata returns the type's metadata
func (t *AzureBearerTokenCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeAzureBearerToken,
		Category:    credential.CategoryCloudIAM,
		Description: "Azure AD Bearer token for Azure service authentication",
		DefaultTTL:  1 * time.Hour, // Azure tokens typically expire in 1 hour
	}
}

// ValidateConfig validates the Config for an Azure Bearer token credential spec
// sourceType determines the validation rules:
// - "azure": requires service principal configuration for token minting
func (t *AzureBearerTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeAzure:
		return t.validateAzureConfig(config)
	default:
		return fmt.Errorf("unsupported source type '%s' for Azure Bearer token; use 'azure'", sourceType)
	}
}

// validateAzureConfig validates config for Azure source
func (t *AzureBearerTokenCredType) validateAzureConfig(config map[string]string) error {
	mintMethod := credential.GetString(config, "mint_method", "bearer_token")

	switch mintMethod {
	case "bearer_token":
		// Pre-provisioned SP credentials are stored in the spec
		return credential.ValidateRequired(config, "client_id", "client_secret", "secret_id")
	default:
		return fmt.Errorf("unsupported mint_method '%s' for azure_bearer_token type; use 'bearer_token'", mintMethod)
	}
}

// Parse converts raw credential data from source into structured Credential
func (t *AzureBearerTokenCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	// Extract access token
	accessToken, ok := rawData["access_token"].(string)
	if !ok || accessToken == "" {
		return nil, fmt.Errorf("%w: missing or invalid access_token", credential.ErrInvalidCredential)
	}

	// Build credential data map
	data := map[string]string{
		"access_token": accessToken,
	}

	// Copy optional fields
	if resourceURI, ok := rawData["resource_uri"].(string); ok {
		data["resource_uri"] = resourceURI
	}
	if tenantID, ok := rawData["tenant_id"].(string); ok {
		data["tenant_id"] = tenantID
	}
	if clientID, ok := rawData["client_id"].(string); ok {
		data["client_id"] = clientID
	}
	if tokenType, ok := rawData["token_type"].(string); ok {
		data["token_type"] = tokenType
	}

	cred := &credential.Credential{
		Type:      credential.TypeAzureBearerToken,
		Category:  credential.CategoryCloudIAM,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: false, // Azure tokens expire naturally and cannot be revoked
		Data:      data,
	}

	return cred, nil
}

// Validate checks if credential data is well-formed
func (t *AzureBearerTokenCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeAzureBearerToken {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeAzureBearerToken, cred.Type)
	}

	// Validate access token exists
	accessToken, ok := cred.Data["access_token"]
	if !ok || accessToken == "" {
		return fmt.Errorf("%w: missing access_token", credential.ErrInvalidCredential)
	}

	return nil
}

// Revoke releases the credential (no-op for Azure tokens)
func (t *AzureBearerTokenCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	// Azure bearer tokens cannot be revoked - they expire naturally
	// This is a no-op
	return nil
}

// RequiresSpecRotation indicates that Azure Bearer Token specs embed SP credentials
// (client_secret, secret_id) that must be rotated. rotation_period is mandatory.
func (t *AzureBearerTokenCredType) RequiresSpecRotation() bool {
	return true
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *AzureBearerTokenCredType) SensitiveConfigFields() []string {
	return []string{"client_secret", "secret_id"}
}

// FieldSchemas returns metadata about the credential's data fields
func (t *AzureBearerTokenCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"access_token": {
			Description: "Azure AD Bearer token for API authentication",
			Sensitive:   true,
		},
		"resource_uri": {
			Description: "Azure resource URI the token is scoped to",
			Sensitive:   false,
		},
		"tenant_id": {
			Description: "Azure AD tenant ID",
			Sensitive:   false,
		},
		"client_id": {
			Description: "Service Principal application/client ID",
			Sensitive:   false,
		},
		"token_type": {
			Description: "Token type (typically 'Bearer')",
			Sensitive:   false,
		},
	}
}
