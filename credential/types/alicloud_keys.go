package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// AlicloudKeysCredType handles Alibaba Cloud (Alicloud) API key credentials.
// A single access key pair serves both the REST API (ACS3-HMAC-SHA256 signing)
// and OSS Object Storage (S3-compatible, AWS SigV4 signing).
// An optional security_token is included for STS temporary credentials.
type AlicloudKeysCredType struct{}

// Metadata returns the type's metadata
func (t *AlicloudKeysCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeAlicloudKeys,
		Category:    credential.CategoryCloudIAM,
		Description: "Alibaba Cloud API keys (access_key_id + access_key_secret for REST API and OSS, optional security_token for STS)",
		DefaultTTL:  0,
	}
}

// ConfigSchema returns the declarative schema for Alicloud key credential config
func (t *AlicloudKeysCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("access_key_id").
			Describe("Alicloud access key ID (usually starts with LTAI)").
			Example("LTAIxxxxxxxxxxxxxxxx"),

		credential.StringField("access_key_secret").
			Describe("Alicloud access key secret").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("security_token").
			Describe("STS security token (optional, for temporary credentials)").
			Example(""),

		credential.StringField("mint_method").
			OneOf("static_alicloud", "assume_role").
			Describe("Mint method for credential minting. Use static_alicloud with a hvault source, or assume_role with an alicloud source.").
			Example("assume_role"),

		// Vault source fields
		credential.StringField("kv2_mount").
			Describe("Vault KV2 mount path (required for static_alicloud)").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to secret in KV2 (required for static_alicloud)").
			Example("alicloud/prod/keys"),

		// STS assume_role fields
		credential.StringField("role_arn").
			Describe("RAM role ARN to assume (required for assume_role)").
			Example("acs:ram::123456789012:role/warden-role"),

		credential.StringField("role_session_name").
			Describe("Session name for the assumed role (default: warden-session)").
			Example("warden-session"),

		credential.StringField("policy").
			Describe("Optional inline policy to further restrict the assumed role").
			Example(""),

		credential.DurationField("duration_seconds").
			Describe("STS credential validity (900s-3600s, default 3600s)").
			Example("3600s"),
	}
}

// ValidateConfig validates the Config for an Alicloud credential spec
func (t *AlicloudKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeVault, credential.SourceTypeAlicloud:
		// Supported
	default:
		return fmt.Errorf("alicloud_keys credentials require a vault or alicloud source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	switch sourceType {
	case credential.SourceTypeVault:
		if config["mint_method"] != "static_alicloud" {
			return fmt.Errorf("'mint_method' must be 'static_alicloud' for vault source, got: %s", config["mint_method"])
		}
		if config["kv2_mount"] == "" {
			return fmt.Errorf("'kv2_mount' is required when mint_method is static_alicloud")
		}
		if config["secret_path"] == "" {
			return fmt.Errorf("'secret_path' is required when mint_method is static_alicloud")
		}
	case credential.SourceTypeAlicloud:
		mintMethod := config["mint_method"]
		if mintMethod != "assume_role" {
			return fmt.Errorf("'mint_method' must be 'assume_role' for alicloud source, got: %s", mintMethod)
		}
		if config["role_arn"] == "" {
			return fmt.Errorf("'role_arn' is required for assume_role")
		}
	}

	return nil
}

// Parse converts raw credential data from source into structured Credential
func (t *AlicloudKeysCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	accessKeyID, ok := rawData["access_key_id"].(string)
	if !ok || accessKeyID == "" {
		return nil, fmt.Errorf("%w: missing or invalid access_key_id", credential.ErrInvalidCredential)
	}

	accessKeySecret, ok := rawData["access_key_secret"].(string)
	if !ok || accessKeySecret == "" {
		return nil, fmt.Errorf("%w: missing or invalid access_key_secret", credential.ErrInvalidCredential)
	}

	data := map[string]string{
		"access_key_id":     accessKeyID,
		"access_key_secret": accessKeySecret,
	}

	if securityToken, ok := rawData["security_token"].(string); ok && securityToken != "" {
		data["security_token"] = securityToken
	}

	return &credential.Credential{
		Type:      credential.TypeAlicloudKeys,
		Category:  credential.CategoryCloudIAM,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: leaseTTL > 0,
		Data:      data,
	}, nil
}

// Validate checks if credential data is well-formed
func (t *AlicloudKeysCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeAlicloudKeys {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeAlicloudKeys, cred.Type)
	}

	if cred.Data["access_key_id"] == "" {
		return fmt.Errorf("%w: missing access_key_id", credential.ErrInvalidCredential)
	}

	if cred.Data["access_key_secret"] == "" {
		return fmt.Errorf("%w: missing access_key_secret", credential.ErrInvalidCredential)
	}

	return nil
}

// Revoke releases the credential (best-effort).
// Revocation is delegated to the SourceDriver when a LeaseID is present.
func (t *AlicloudKeysCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	if cred.LeaseID == "" {
		return nil
	}
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}
	return nil
}

// RequiresSpecRotation returns false — Alicloud keys don't embed rotatable credentials in spec config
func (t *AlicloudKeysCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *AlicloudKeysCredType) SensitiveConfigFields() []string {
	return []string{"access_key_secret", "security_token"}
}

// FieldSchemas returns metadata about the credential's data fields
func (t *AlicloudKeysCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"access_key_id": {
			Description: "Alicloud access key ID",
			Sensitive:   false,
		},
		"access_key_secret": {
			Description: "Alicloud access key secret",
			Sensitive:   true,
		},
		"security_token": {
			Description: "Alicloud STS security token (for temporary credentials)",
			Sensitive:   true,
		},
	}
}
