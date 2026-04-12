package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// CloudflareKeysCredType handles Cloudflare cloud credentials.
// A single credential holds an API token for the REST API and
// S3-compatible access_key_id + secret_access_key for R2 Object Storage (SigV4).
type CloudflareKeysCredType struct{}

// Metadata returns the type's metadata
func (t *CloudflareKeysCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeCloudflareKeys,
		Category:    credential.CategoryCloudIAM,
		Description: "Cloudflare keys (api_token for REST API, access_key_id + secret_access_key for R2 Object Storage)",
		DefaultTTL:  0,
	}
}

// ConfigSchema returns the declarative schema for Cloudflare key credential config
func (t *CloudflareKeysCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("access_key_id").
			Describe("Cloudflare R2 access key ID").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("secret_access_key").
			Describe("Cloudflare R2 secret access key").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("api_token").
			Describe("Cloudflare API bearer token for REST API").
			Example("v1.0-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("mint_method").
			OneOf("static_keys", "static_cloudflare").
			Describe("Mint method for credential minting").
			Example("static_keys"),

		// Vault source fields
		credential.StringField("kv2_mount").
			Describe("Vault KV2 mount path (required for static_cloudflare)").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to secret in KV2 (required for static_cloudflare)").
			Example("cloudflare/prod/keys"),
	}
}

// ValidateConfig validates the Config for a Cloudflare credential spec
func (t *CloudflareKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeLocal, credential.SourceTypeVault:
		// Supported
	default:
		return fmt.Errorf("cloudflare_keys credentials require a local or vault source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	switch sourceType {
	case credential.SourceTypeVault:
		if config["mint_method"] != "static_cloudflare" {
			return fmt.Errorf("'mint_method' must be 'static_cloudflare' for vault source, got: %s", config["mint_method"])
		}
		if config["kv2_mount"] == "" {
			return fmt.Errorf("'kv2_mount' is required when mint_method is static_cloudflare")
		}
		if config["secret_path"] == "" {
			return fmt.Errorf("'secret_path' is required when mint_method is static_cloudflare")
		}
	default:
		hasAPI := config["api_token"] != ""
		hasR2 := config["access_key_id"] != "" || config["secret_access_key"] != ""
		if !hasAPI && !hasR2 {
			return fmt.Errorf("at least one of 'api_token' (for API) or 'access_key_id'+'secret_access_key' (for R2) is required")
		}
		// If R2 fields are partially set, both must be present
		if config["access_key_id"] != "" && config["secret_access_key"] == "" {
			return fmt.Errorf("'secret_access_key' is required when 'access_key_id' is set")
		}
		if config["secret_access_key"] != "" && config["access_key_id"] == "" {
			return fmt.Errorf("'access_key_id' is required when 'secret_access_key' is set")
		}
	}

	return nil
}

// Parse converts raw credential data from source into structured Credential.
// At least one mode must be present: api_token (API) or access_key_id+secret_access_key (R2).
func (t *CloudflareKeysCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	accessKeyID, _ := rawData["access_key_id"].(string)
	secretAccessKey, _ := rawData["secret_access_key"].(string)
	apiToken, _ := rawData["api_token"].(string)

	// Partial R2 credentials are invalid — check this first
	if (accessKeyID != "" && secretAccessKey == "") || (accessKeyID == "" && secretAccessKey != "") {
		return nil, fmt.Errorf("%w: both access_key_id and secret_access_key are required for R2", credential.ErrInvalidCredential)
	}

	hasAPI := apiToken != ""
	hasR2 := accessKeyID != "" && secretAccessKey != ""

	if !hasAPI && !hasR2 {
		return nil, fmt.Errorf("%w: at least one of api_token or access_key_id+secret_access_key is required", credential.ErrInvalidCredential)
	}

	data := make(map[string]string)
	if apiToken != "" {
		data["api_token"] = apiToken
	}
	if accessKeyID != "" {
		data["access_key_id"] = accessKeyID
	}
	if secretAccessKey != "" {
		data["secret_access_key"] = secretAccessKey
	}

	return &credential.Credential{
		Type:      credential.TypeCloudflareKeys,
		Category:  credential.CategoryCloudIAM,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: leaseTTL > 0,
		Data:      data,
	}, nil
}

// Validate checks if credential data is well-formed.
// At least one mode must be present: api_token (API) or access_key_id+secret_access_key (R2).
func (t *CloudflareKeysCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeCloudflareKeys {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeCloudflareKeys, cred.Type)
	}

	// Partial R2 credentials are invalid — check this first
	if (cred.Data["access_key_id"] != "" && cred.Data["secret_access_key"] == "") ||
		(cred.Data["access_key_id"] == "" && cred.Data["secret_access_key"] != "") {
		return fmt.Errorf("%w: both access_key_id and secret_access_key are required for R2", credential.ErrInvalidCredential)
	}

	hasAPI := cred.Data["api_token"] != ""
	hasR2 := cred.Data["access_key_id"] != "" && cred.Data["secret_access_key"] != ""

	if !hasAPI && !hasR2 {
		return fmt.Errorf("%w: at least one of api_token or access_key_id+secret_access_key is required", credential.ErrInvalidCredential)
	}

	return nil
}

// Revoke releases the credential (best-effort).
// Revocation is delegated to the SourceDriver when a LeaseID is present.
func (t *CloudflareKeysCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	if cred.LeaseID == "" {
		return nil
	}
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}
	return nil
}

// RequiresSpecRotation returns false — Cloudflare keys don't embed rotatable credentials in spec config
func (t *CloudflareKeysCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *CloudflareKeysCredType) SensitiveConfigFields() []string {
	return []string{"secret_access_key", "api_token"}
}

// FieldSchemas returns metadata about the credential's data fields
func (t *CloudflareKeysCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"access_key_id": {
			Description: "Cloudflare R2 access key ID",
			Sensitive:   false,
		},
		"secret_access_key": {
			Description: "Cloudflare R2 secret access key",
			Sensitive:   true,
		},
		"api_token": {
			Description: "Cloudflare API bearer token",
			Sensitive:   true,
		},
	}
}
