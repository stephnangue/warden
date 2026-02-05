package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// VaultTokenCredType handles HashiCorp Vault authentication tokens
type VaultTokenCredType struct{}

// Metadata returns the type's metadata
func (t *VaultTokenCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeVaultToken,
		Category:    credential.CategoryAPI,
		Description: "HashiCorp Vault authentication token",
		DefaultTTL:  1 * time.Hour,
	}
}

// ValidateConfig validates the Config for a Vault token credential spec
// sourceType determines the validation rules:
// - "hvault": requires auth configuration to generate tokens
func (t *VaultTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeVault:
		return t.validateVaultConfig(config)
	default:
		return fmt.Errorf("unsupported source type '%s' for Vault token", sourceType)
	}
}

// validateVaultConfig validates config for Vault source
// Requires mint_method to route to the correct minting strategy
func (t *VaultTokenCredType) validateVaultConfig(config map[string]string) error {
	mintMethod := credential.GetString(config, "mint_method", "")
	if mintMethod == "" {
		return fmt.Errorf("'mint_method' is required for vault source (use 'vault_token')")
	}

	switch mintMethod {
	case "vault_token":
		return credential.ValidateRequired(config, "mint_method", "token_role")
	default:
		return fmt.Errorf("unsupported mint_method '%s' for vault_token type; use 'vault_token'", mintMethod)
	}
}

// Parse converts raw credential data from source into structured Credential
func (t *VaultTokenCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	// Extract token (may be named "token" or "client_token" from Vault)
	token, ok := rawData["token"].(string)
	if !ok || token == "" {
		// Try alternative field name used by Vault auth responses
		token, ok = rawData["client_token"].(string)
		if !ok || token == "" {
			return nil, fmt.Errorf("%w: missing or invalid token", credential.ErrInvalidCredential)
		}
	}

	cred := &credential.Credential{
		Type:      credential.TypeVaultToken,
		Category:  credential.CategoryAPI,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: leaseTTL > 0,
		Data: map[string]string{
			"token": token,
		},
	}

	return cred, nil
}

// Validate checks if credential data is well-formed
func (t *VaultTokenCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeVaultToken {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeVaultToken, cred.Type)
	}

	// Validate token
	token, ok := cred.Data["token"]
	if !ok || token == "" {
		return fmt.Errorf("%w: missing token", credential.ErrInvalidCredential)
	}

	// Vault tokens are typically prefixed with "hvs." (Vault service token) or "s." (legacy)
	// but we don't strictly enforce this as custom tokens may exist

	return nil
}

// Revoke releases the credential (best-effort)
func (t *VaultTokenCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	// Only dynamic tokens with a lease can be revoked
	if cred.LeaseID == "" {
		return nil // Static tokens cannot be revoked through Warden
	}

	// Attempt revocation through the driver
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}

	return nil
}

// CanRotate indicates if this type supports proactive rotation
func (t *VaultTokenCredType) CanRotate() bool {
	return true // Vault tokens can be rotated
}

// FieldSchemas returns metadata about the credential's data fields
func (t *VaultTokenCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"token": {
			Description: "HashiCorp Vault authentication token",
			Sensitive:   true,
		},
	}
}
