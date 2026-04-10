package types

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
)

// ScalewayKeysCredType handles Scaleway API key credentials.
// A single key pair serves both the standard API (secret_key as X-Auth-Token)
// and S3 Object Storage (access_key + secret_key for SigV4 signing).
type ScalewayKeysCredType struct{}

// Metadata returns the type's metadata
func (t *ScalewayKeysCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeScalewayKeys,
		Category:    credential.CategoryCloudIAM,
		Description: "Scaleway API keys (access key + secret key for API and S3 Object Storage)",
		DefaultTTL:  0, // Static keys have no default TTL
	}
}

// ConfigSchema returns the declarative schema for Scaleway key credential config
func (t *ScalewayKeysCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("access_key").
			Describe("Scaleway access key (starts with SCW)").
			Example("SCWXXXXXXXXXXXXXXXXX"),

		credential.StringField("secret_key").
			Describe("Scaleway secret key (UUID format)").
			Example("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),

		credential.StringField("mint_method").
			OneOf("static_scaleway", "static_keys", "dynamic_keys").
			Describe("Mint method for credential minting").
			Example("static_keys"),

		// Vault source fields
		credential.StringField("kv2_mount").
			Describe("Vault KV2 mount path (required for static_scaleway)").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to secret in KV2 (required for static_scaleway)").
			Example("scaleway/prod/keys"),

		// Scaleway dynamic_keys fields
		credential.StringField("application_id").
			Describe("IAM application ID to create keys for (required for dynamic_keys)").
			Example("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),

		credential.StringField("default_project_id").
			Describe("Default project ID for Object Storage (optional)").
			Example("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),

		credential.StringField("description").
			Describe("Description for dynamically created keys (max 200 chars)").
			Example("warden-managed-key"),

		credential.DurationField("ttl").
			Describe("TTL for dynamically created keys (default: 1h)").
			Example("1h"),
	}
}

// ValidateConfig validates the Config for a Scaleway credential spec
func (t *ScalewayKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeLocal, credential.SourceTypeVault, credential.SourceTypeScaleway:
		// Supported
	default:
		return fmt.Errorf("scaleway_keys credentials require a local, vault, or scaleway source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	switch sourceType {
	case credential.SourceTypeVault:
		if config["mint_method"] != "static_scaleway" {
			return fmt.Errorf("'mint_method' must be 'static_scaleway' for vault source, got: %s", config["mint_method"])
		}
		if config["kv2_mount"] == "" {
			return fmt.Errorf("'kv2_mount' is required when mint_method is static_scaleway")
		}
		if config["secret_path"] == "" {
			return fmt.Errorf("'secret_path' is required when mint_method is static_scaleway")
		}
	case credential.SourceTypeScaleway:
		mintMethod := config["mint_method"]
		switch mintMethod {
		case "static_keys":
			if config["access_key"] == "" {
				return fmt.Errorf("'access_key' is required for static_keys")
			}
			if config["secret_key"] == "" {
				return fmt.Errorf("'secret_key' is required for static_keys")
			}
		case "dynamic_keys":
			if config["application_id"] == "" {
				return fmt.Errorf("'application_id' is required for dynamic_keys")
			}
		default:
			return fmt.Errorf("'mint_method' must be 'static_keys' or 'dynamic_keys' for scaleway source, got: %s", mintMethod)
		}
	default:
		if config["access_key"] == "" {
			return fmt.Errorf("'access_key' is required")
		}
		if config["secret_key"] == "" {
			return fmt.Errorf("'secret_key' is required")
		}
	}

	return nil
}

// Parse converts raw credential data from source into structured Credential
func (t *ScalewayKeysCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	accessKey, ok := rawData["access_key"].(string)
	if !ok || accessKey == "" {
		return nil, fmt.Errorf("%w: missing or invalid access_key", credential.ErrInvalidCredential)
	}

	secretKey, ok := rawData["secret_key"].(string)
	if !ok || secretKey == "" {
		return nil, fmt.Errorf("%w: missing or invalid secret_key", credential.ErrInvalidCredential)
	}

	return &credential.Credential{
		Type:      credential.TypeScalewayKeys,
		Category:  credential.CategoryCloudIAM,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: leaseTTL > 0,
		Data: map[string]string{
			"access_key": accessKey,
			"secret_key": secretKey,
		},
	}, nil
}

// Validate checks if credential data is well-formed
func (t *ScalewayKeysCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeScalewayKeys {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeScalewayKeys, cred.Type)
	}

	accessKey, ok := cred.Data["access_key"]
	if !ok || accessKey == "" {
		return fmt.Errorf("%w: missing access_key", credential.ErrInvalidCredential)
	}

	if !strings.HasPrefix(accessKey, "SCW") {
		return fmt.Errorf("%w: invalid access_key format (must start with SCW)", credential.ErrInvalidCredential)
	}

	secretKey, ok := cred.Data["secret_key"]
	if !ok || secretKey == "" {
		return fmt.Errorf("%w: missing secret_key", credential.ErrInvalidCredential)
	}

	return nil
}

// Revoke releases the credential (best-effort).
// Scaleway API keys can be deleted via DELETE /iam/v1alpha1/api-keys/{access_key}.
// Revocation is delegated to the SourceDriver when a LeaseID is present.
func (t *ScalewayKeysCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	if cred.LeaseID == "" {
		return nil // Static credentials without a lease cannot be revoked
	}
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}
	return nil
}

// RequiresSpecRotation returns false — Scaleway keys don't embed rotatable credentials in spec config
func (t *ScalewayKeysCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *ScalewayKeysCredType) SensitiveConfigFields() []string {
	return []string{"secret_key"}
}

// FieldSchemas returns metadata about the credential's data fields
func (t *ScalewayKeysCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"access_key": {
			Description: "Scaleway access key",
			Sensitive:   false,
		},
		"secret_key": {
			Description: "Scaleway secret key",
			Sensitive:   true,
		},
	}
}
