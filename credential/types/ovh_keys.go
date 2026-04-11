package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// OVHKeysCredType handles OVH cloud credentials.
// A single credential holds an API token for the REST API and
// S3-compatible access_key + secret_key for Object Storage (SigV4).
type OVHKeysCredType struct{}

// Metadata returns the type's metadata
func (t *OVHKeysCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeOVHKeys,
		Category:    credential.CategoryCloudIAM,
		Description: "OVH keys (api_token for REST API, access_key + secret_key for S3 Object Storage)",
		DefaultTTL:  0,
	}
}

// ConfigSchema returns the declarative schema for OVH key credential config
func (t *OVHKeysCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("access_key").
			Describe("OVH S3 access key").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("secret_key").
			Describe("OVH S3 secret key").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("api_token").
			Describe("OVH API bearer token for REST API").
			Example("eyJhbGciOiJSUzI1NiIs..."),

		credential.StringField("mint_method").
			OneOf("static_keys", "static_ovh").
			Describe("Mint method for credential minting").
			Example("static_keys"),

		// Vault source fields
		credential.StringField("kv2_mount").
			Describe("Vault KV2 mount path (required for static_ovh)").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to secret in KV2 (required for static_ovh)").
			Example("ovh/prod/keys"),
	}
}

// ValidateConfig validates the Config for an OVH credential spec
func (t *OVHKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeLocal, credential.SourceTypeVault:
		// Supported
	default:
		return fmt.Errorf("ovh_keys credentials require a local or vault source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	switch sourceType {
	case credential.SourceTypeVault:
		if config["mint_method"] != "static_ovh" {
			return fmt.Errorf("'mint_method' must be 'static_ovh' for vault source, got: %s", config["mint_method"])
		}
		if config["kv2_mount"] == "" {
			return fmt.Errorf("'kv2_mount' is required when mint_method is static_ovh")
		}
		if config["secret_path"] == "" {
			return fmt.Errorf("'secret_path' is required when mint_method is static_ovh")
		}
	default:
		if config["access_key"] == "" {
			return fmt.Errorf("'access_key' is required")
		}
		if config["secret_key"] == "" {
			return fmt.Errorf("'secret_key' is required")
		}
		if config["api_token"] == "" {
			return fmt.Errorf("'api_token' is required")
		}
	}

	return nil
}

// Parse converts raw credential data from source into structured Credential
func (t *OVHKeysCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	accessKey, ok := rawData["access_key"].(string)
	if !ok || accessKey == "" {
		return nil, fmt.Errorf("%w: missing or invalid access_key", credential.ErrInvalidCredential)
	}

	secretKey, ok := rawData["secret_key"].(string)
	if !ok || secretKey == "" {
		return nil, fmt.Errorf("%w: missing or invalid secret_key", credential.ErrInvalidCredential)
	}

	apiToken, ok := rawData["api_token"].(string)
	if !ok || apiToken == "" {
		return nil, fmt.Errorf("%w: missing or invalid api_token", credential.ErrInvalidCredential)
	}

	return &credential.Credential{
		Type:      credential.TypeOVHKeys,
		Category:  credential.CategoryCloudIAM,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: leaseTTL > 0,
		Data: map[string]string{
			"access_key": accessKey,
			"secret_key": secretKey,
			"api_token":  apiToken,
		},
	}, nil
}

// Validate checks if credential data is well-formed
func (t *OVHKeysCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeOVHKeys {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeOVHKeys, cred.Type)
	}

	if cred.Data["access_key"] == "" {
		return fmt.Errorf("%w: missing access_key", credential.ErrInvalidCredential)
	}
	if cred.Data["secret_key"] == "" {
		return fmt.Errorf("%w: missing secret_key", credential.ErrInvalidCredential)
	}
	if cred.Data["api_token"] == "" {
		return fmt.Errorf("%w: missing api_token", credential.ErrInvalidCredential)
	}

	return nil
}

// Revoke releases the credential (best-effort).
// Revocation is delegated to the SourceDriver when a LeaseID is present.
func (t *OVHKeysCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	if cred.LeaseID == "" {
		return nil
	}
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}
	return nil
}

// RequiresSpecRotation returns false — OVH keys don't embed rotatable credentials in spec config
func (t *OVHKeysCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *OVHKeysCredType) SensitiveConfigFields() []string {
	return []string{"secret_key", "api_token"}
}

// FieldSchemas returns metadata about the credential's data fields
func (t *OVHKeysCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"access_key": {
			Description: "OVH S3 access key",
			Sensitive:   false,
		},
		"secret_key": {
			Description: "OVH S3 secret key",
			Sensitive:   true,
		},
		"api_token": {
			Description: "OVH API bearer token",
			Sensitive:   true,
		},
	}
}
