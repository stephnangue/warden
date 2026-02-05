package types

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
)

// AWSIAMAccessKeysCredType handles AWS IAM access keys (static and STS temporary)
type AWSIAMAccessKeysCredType struct{}

// Metadata returns the type's metadata
func (t *AWSIAMAccessKeysCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeAWSAccessKeys,
		Category:    credential.CategoryCloudIAM,
		Description: "AWS IAM access keys (static and STS temporary credentials)",
		DefaultTTL:  12 * time.Hour,
	}
}

// ValidateConfig validates the Config for an AWS credential spec
// sourceName determines the validation rules:
// - "local": only access_key_id and secret_access_key are allowed
// - "vault": requires aws_mount/role_name (dynamic) or kv2_mount/secret_path (static KV)
func (t *AWSIAMAccessKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeLocal:
		return t.validateLocalConfig(config)
	case credential.SourceTypeVault:
		return t.validateVaultConfig(config)
	case credential.SourceTypeAWS:
		return t.validateAWSConfig(config)
	default:
		return fmt.Errorf("unsupported source type '%s' for AWS credentials", sourceType)
	}
}

// validateLocalConfig validates config for local source
// Only access_key_id and secret_access_key are accepted
func (t *AWSIAMAccessKeysCredType) validateLocalConfig(config map[string]string) error {
	// Define allowed fields
	allowedFields := map[string]bool{
		"access_key_id":     true,
		"secret_access_key": true,
	}

	// Check for invalid fields first and provide helpful error
	var invalidFields []string
	for key := range config {
		if !allowedFields[key] {
			invalidFields = append(invalidFields, key)
		}
	}
	if len(invalidFields) > 0 {
		return fmt.Errorf("invalid config field(s) %v; expected: access_key_id, secret_access_key", invalidFields)
	}

	// Validate required fields
	if err := credential.ValidateRequired(config, "access_key_id", "secret_access_key"); err != nil {
		return err
	}

	return nil
}

// validateVaultConfig validates config for Vault source
// Requires mint_method to route to the correct minting strategy
func (t *AWSIAMAccessKeysCredType) validateVaultConfig(config map[string]string) error {
	mintMethod := credential.GetString(config, "mint_method", "")
	if mintMethod == "" {
		return fmt.Errorf("'mint_method' is required for vault source (use 'kv2_static' or 'dynamic_aws')")
	}

	switch mintMethod {
	case "kv2_static":
		return credential.ValidateRequired(config, "mint_method", "kv2_mount", "secret_path")
	case "dynamic_aws":
		return credential.ValidateRequired(config, "mint_method", "aws_mount", "role_name")
	default:
		return fmt.Errorf("unsupported mint_method '%s' for aws_access_keys with vault source; use 'kv2_static' or 'dynamic_aws'", mintMethod)
	}
}

// validateAWSConfig validates config for AWS source
// Requires mint_method to route between STS AssumeRole and Secrets Manager
func (t *AWSIAMAccessKeysCredType) validateAWSConfig(config map[string]string) error {
	mintMethod := credential.GetString(config, "mint_method", "")
	if mintMethod == "" {
		return fmt.Errorf("'mint_method' is required for aws source (use 'sts_assume_role' or 'secrets_manager')")
	}

	switch mintMethod {
	case "sts_assume_role":
		return credential.ValidateRequired(config, "mint_method", "role_arn")
	case "secrets_manager":
		return credential.ValidateRequired(config, "mint_method", "secret_id")
	default:
		return fmt.Errorf("unsupported mint_method '%s'; use 'sts_assume_role' or 'secrets_manager'", mintMethod)
	}
}

// Parse converts raw credential data from source into structured Credential
func (t *AWSIAMAccessKeysCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	// Extract access_key_id (may be named "access_key" from Vault AWS engine)
	accessKeyID, ok := rawData["access_key_id"].(string)
	if !ok || accessKeyID == "" {
		// Try alternative field name used by Vault AWS engine
		accessKeyID, ok = rawData["access_key"].(string)
		if !ok || accessKeyID == "" {
			return nil, fmt.Errorf("%w: missing or invalid access_key_id", credential.ErrInvalidCredential)
		}
	}

	// Extract secret_access_key (may be named "secret_key" from Vault AWS engine)
	secretAccessKey, ok := rawData["secret_access_key"].(string)
	if !ok || secretAccessKey == "" {
		// Try alternative field name used by Vault AWS engine
		secretAccessKey, ok = rawData["secret_key"].(string)
		if !ok || secretAccessKey == "" {
			return nil, fmt.Errorf("%w: missing or invalid secret_access_key", credential.ErrInvalidCredential)
		}
	}

	cred := &credential.Credential{
		Type:      credential.TypeAWSAccessKeys,
		Category:  credential.CategoryCloudIAM,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: leaseTTL > 0, // STS temporary credentials are revocable
		Data: map[string]string{
			"access_key_id":     accessKeyID,
			"secret_access_key": secretAccessKey,
		},
	}

	// Extract optional session token (for STS temporary credentials)
	if sessionToken, ok := rawData["session_token"].(string); ok && sessionToken != "" {
		cred.Data["session_token"] = sessionToken
	}

	// Extract optional security token (alternative name for session_token)
	if securityToken, ok := rawData["security_token"].(string); ok && securityToken != "" {
		cred.Data["security_token"] = securityToken
	}

	// Extract optional credential source
	if credSource, ok := rawData["cred_source"].(string); ok && credSource != "" {
		cred.SourceType = credSource
	}

	return cred, nil
}

// Validate checks if credential data is well-formed
func (t *AWSIAMAccessKeysCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeAWSAccessKeys {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeAWSAccessKeys, cred.Type)
	}

	// Validate access_key_id
	accessKeyID, ok := cred.Data["access_key_id"]
	if !ok || accessKeyID == "" {
		return fmt.Errorf("%w: missing access_key_id", credential.ErrInvalidCredential)
	}

	// AWS access key IDs start with "AKIA" (IAM user) or "ASIA" (STS temporary)
	if !strings.HasPrefix(accessKeyID, "AKIA") && !strings.HasPrefix(accessKeyID, "ASIA") {
		return fmt.Errorf("%w: invalid access_key_id format (must start with AKIA or ASIA)", credential.ErrInvalidCredential)
	}

	// Validate secret_access_key
	secretAccessKey, ok := cred.Data["secret_access_key"]
	if !ok || secretAccessKey == "" {
		return fmt.Errorf("%w: missing secret_access_key", credential.ErrInvalidCredential)
	}

	// Secret access keys are 40 characters long
	if len(secretAccessKey) != 40 {
		return fmt.Errorf("%w: invalid secret_access_key length (must be 40 characters)", credential.ErrInvalidCredential)
	}

	// If this is an STS temporary credential (ASIA prefix), validate session token
	if strings.HasPrefix(accessKeyID, "ASIA") {
		sessionToken, hasSession := cred.Data["session_token"]
		securityToken, hasSecurity := cred.Data["security_token"]

		if (!hasSession || sessionToken == "") && (!hasSecurity || securityToken == "") {
			return fmt.Errorf("%w: STS temporary credentials require session_token or security_token", credential.ErrInvalidCredential)
		}
	}

	return nil
}

// Revoke releases the credential (best-effort)
func (t *AWSIAMAccessKeysCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	// Only STS temporary credentials with a lease can be revoked
	if cred.LeaseID == "" {
		return nil // Static IAM credentials cannot be revoked
	}

	// Attempt revocation through the driver
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}

	return nil
}

// CanRotate indicates if this type supports proactive rotation
func (t *AWSIAMAccessKeysCredType) CanRotate() bool {
	return true // AWS credentials support rotation
}

// FieldSchemas returns metadata about the credential's data fields
func (t *AWSIAMAccessKeysCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"access_key_id": {
			Description: "AWS access key ID",
			Sensitive:   false,
		},
		"secret_access_key": {
			Description: "AWS secret access key",
			Sensitive:   true,
		},
		"session_token": {
			Description: "AWS session token for temporary credentials",
			Sensitive:   true,
		},
		"security_token": {
			Description: "AWS security token (alternative to session_token)",
			Sensitive:   true,
		},
	}
}
