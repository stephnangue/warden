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

// ConfigSchema returns the declarative schema for AWS access keys credential config
func (t *AWSIAMAccessKeysCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		// Local source fields
		credential.StringField("access_key_id").
			Describe("AWS access key ID (required for local source)").
			Example("AKIAIOSFODNN7EXAMPLE"),

		credential.StringField("secret_access_key").
			Describe("AWS secret access key (required for local source)").
			Example("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),

		// Common field for vault and aws sources
		credential.StringField("mint_method").
			OneOf("kv2_static", "dynamic_aws", "sts_assume_role", "secrets_manager").
			Describe("Method for minting AWS credentials").
			Example("sts_assume_role"),

		// Vault source - KV2 static fields
		credential.StringField("kv2_mount").
			Describe("Vault KV2 mount path (required for kv2_static)").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to secret in KV2 (required for kv2_static)").
			Example("aws/prod/keys"),

		// Vault source - Dynamic AWS fields
		credential.StringField("aws_mount").
			Describe("Vault AWS secrets engine mount (required for dynamic_aws)").
			Example("aws"),

		credential.StringField("role_name").
			Describe("Vault AWS role name (required for dynamic_aws)").
			Example("app-backend-role"),

		// AWS source - STS AssumeRole fields
		credential.StringField("role_arn").
			Describe("IAM role ARN to assume (required for sts_assume_role)").
			Example("arn:aws:iam::123456789012:role/app-backend"),

		credential.DurationField("ttl").
			Describe("Session duration for assumed role (defaults to 1h)").
			Example("1h"),

		credential.StringField("session_name").
			Describe("Session name for assumed role (defaults to warden-{spec-name})").
			Example("warden-session"),

		credential.StringField("external_id").
			Describe("External ID for STS AssumeRole (optional security measure)").
			Example("unique-external-id-123"),

		credential.StringField("policy").
			Describe("IAM policy to further restrict assumed role permissions (optional)").
			Example("{\"Version\":\"2012-10-17\",\"Statement\":[...]}"),

		// AWS source - Secrets Manager fields
		credential.StringField("secret_id").
			Describe("AWS Secrets Manager secret ID (required for secrets_manager)").
			Example("prod/aws/keys"),

		credential.StringField("version_stage").
			Describe("Version stage to retrieve (optional, defaults to AWSCURRENT)").
			Example("AWSCURRENT"),

		credential.StringField("version_id").
			Describe("Specific version ID to retrieve (optional)").
			Example("uuid-version-id"),
	}
}

// ValidateConfig validates the Config for an AWS credential spec
// sourceName determines the validation rules:
// - "local": only access_key_id and secret_access_key are allowed
// - "vault": requires aws_mount/role_name (dynamic) or kv2_mount/secret_path (static KV)
// - "aws": requires sts_assume_role (role_arn) or secrets_manager (secret_id)
func (t *AWSIAMAccessKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility
	switch sourceType {
	case credential.SourceTypeLocal, credential.SourceTypeVault, credential.SourceTypeAWS:
		// Supported
	default:
		return fmt.Errorf("aws_access_keys credentials require a local, vault, or aws source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Step 3: Source-specific conditional validation
	switch sourceType {
	case credential.SourceTypeLocal:
		return t.validateLocalConfig(config)
	case credential.SourceTypeVault:
		return t.validateVaultConfig(config)
	case credential.SourceTypeAWS:
		return t.validateAWSConfig(config)
	}

	return nil
}

// validateLocalConfig validates config for local source
// Only access_key_id and secret_access_key are required
func (t *AWSIAMAccessKeysCredType) validateLocalConfig(config map[string]string) error {
	// Check for invalid fields
	allowedFields := map[string]bool{
		"access_key_id":     true,
		"secret_access_key": true,
	}
	for key := range config {
		if !allowedFields[key] {
			return fmt.Errorf("invalid config field '%s' for local source; only access_key_id and secret_access_key are allowed", key)
		}
	}

	if config["access_key_id"] == "" {
		return fmt.Errorf("'access_key_id' is required for local source")
	}
	if config["secret_access_key"] == "" {
		return fmt.Errorf("'secret_access_key' is required for local source")
	}
	return nil
}

// validateVaultConfig validates config for Vault source
// Requires mint_method to route to the correct minting strategy
func (t *AWSIAMAccessKeysCredType) validateVaultConfig(config map[string]string) error {
	mintMethod := config["mint_method"]
	if mintMethod == "" {
		return fmt.Errorf("'mint_method' is required for vault source")
	}

	switch mintMethod {
	case "kv2_static":
		if config["kv2_mount"] == "" {
			return fmt.Errorf("'kv2_mount' is required when mint_method is kv2_static")
		}
		if config["secret_path"] == "" {
			return fmt.Errorf("'secret_path' is required when mint_method is kv2_static")
		}
	case "dynamic_aws":
		if config["aws_mount"] == "" {
			return fmt.Errorf("'aws_mount' is required when mint_method is dynamic_aws")
		}
		if config["role_name"] == "" {
			return fmt.Errorf("'role_name' is required when mint_method is dynamic_aws")
		}
	}

	return nil
}

// validateAWSConfig validates config for AWS source
// Requires mint_method to route between STS AssumeRole and Secrets Manager
func (t *AWSIAMAccessKeysCredType) validateAWSConfig(config map[string]string) error {
	mintMethod := config["mint_method"]
	if mintMethod == "" {
		return fmt.Errorf("'mint_method' is required for aws source")
	}

	switch mintMethod {
	case "sts_assume_role":
		if config["role_arn"] == "" {
			return fmt.Errorf("'role_arn' is required when mint_method is sts_assume_role")
		}
	case "secrets_manager":
		if config["secret_id"] == "" {
			return fmt.Errorf("'secret_id' is required when mint_method is secrets_manager")
		}
	}

	return nil
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

// RequiresSpecRotation returns false — AWS IAM access key specs don't embed
// rotatable credentials; the source driver handles key rotation.
func (t *AWSIAMAccessKeysCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *AWSIAMAccessKeysCredType) SensitiveConfigFields() []string {
	return nil
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
