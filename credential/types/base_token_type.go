package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// TokenFieldConfig describes how to extract and validate token fields from raw data
type TokenFieldConfig struct {
	// PrimaryField is the main token field name (e.g., "access_token", "token")
	PrimaryField string

	// AlternativeFields are alternative names for the primary field
	// (e.g., Vault uses both "token" and "client_token")
	AlternativeFields []string

	// OptionalFields are additional fields to copy if present
	OptionalFields []string

	// FieldSchemas maps field names to their metadata
	FieldSchemas map[string]*credential.CredentialFieldSchema
}

// BaseTokenType provides common implementation for token-based credential types
// Token types can embed this struct and only implement type-specific methods:
// - ValidateConfig (source-specific validation)
// - RequiresSpecRotation (whether spec embeds credentials)
// - SensitiveConfigFields (config keys to mask)
type BaseTokenType struct {
	TypeMetadata credential.TypeMetadata
	FieldConfig  TokenFieldConfig
	Revocable    bool // Whether tokens with leaseID should be revocable
}

// Metadata returns the type's metadata
func (t *BaseTokenType) Metadata() credential.TypeMetadata {
	return t.TypeMetadata
}

// Parse converts raw credential data from source into structured Credential
func (t *BaseTokenType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	// Extract primary token field
	var token string
	var found bool

	if val, ok := rawData[t.FieldConfig.PrimaryField].(string); ok && val != "" {
		token = val
		found = true
	} else {
		// Try alternative fields
		for _, altField := range t.FieldConfig.AlternativeFields {
			if val, ok := rawData[altField].(string); ok && val != "" {
				token = val
				found = true
				break
			}
		}
	}

	if !found || token == "" {
		return nil, fmt.Errorf("%w: missing or invalid %s", credential.ErrInvalidCredential, t.FieldConfig.PrimaryField)
	}

	// Build credential data map
	data := map[string]string{
		t.FieldConfig.PrimaryField: token,
	}

	// Copy optional fields if present
	for _, field := range t.FieldConfig.OptionalFields {
		if val, ok := rawData[field].(string); ok {
			data[field] = val
		}
	}

	cred := &credential.Credential{
		Type:      t.TypeMetadata.Name,
		Category:  t.TypeMetadata.Category,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: t.Revocable && leaseID != "",
		Data:      data,
	}

	return cred, nil
}

// Validate checks if credential data is well-formed
func (t *BaseTokenType) Validate(cred *credential.Credential) error {
	if cred.Type != t.TypeMetadata.Name {
		return fmt.Errorf("%w: expected type %s, got %s",
			credential.ErrInvalidCredential, t.TypeMetadata.Name, cred.Type)
	}

	// Validate primary token field exists
	token, ok := cred.Data[t.FieldConfig.PrimaryField]
	if !ok || token == "" {
		return fmt.Errorf("%w: missing %s", credential.ErrInvalidCredential, t.FieldConfig.PrimaryField)
	}

	return nil
}

// Revoke releases the credential via the driver (for revocable tokens)
func (t *BaseTokenType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	if !t.Revocable || cred.LeaseID == "" {
		return nil
	}

	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}

	return nil
}

// FieldSchemas returns metadata about the credential's data fields
func (t *BaseTokenType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return t.FieldConfig.FieldSchemas
}
