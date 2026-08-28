package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
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
			OneOf("assume_role").
			Describe("Mint method for credential minting. Use assume_role with an alicloud source.").
			Example("assume_role"),

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
	// A vault source is not supported: it would need a static_alicloud mint method,
	// which the Vault driver has never implemented. It used to be accepted here and
	// then failed at the first mint.
	if sourceType != credential.SourceTypeAlicloud {
		return fmt.Errorf("alicloud_keys credentials require an alicloud source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	if mintMethod := config["mint_method"]; mintMethod != "assume_role" {
		return fmt.Errorf("'mint_method' must be 'assume_role' for alicloud source, got: %s", mintMethod)
	}
	if config["role_arn"] == "" {
		return fmt.Errorf("'role_arn' is required for assume_role")
	}

	return nil
}

// Parse converts raw credential data from source into structured Credential
func (t *AlicloudKeysCredType) Parse(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
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

	meta, err := helper.ToStringMap(metadata)
	if err != nil {
		return nil, err
	}

	return &credential.Credential{
		Type:     credential.TypeAlicloudKeys,
		Category: credential.CategoryCloudIAM,
		LeaseTTL: leaseTTL,
		LeaseID:  leaseID,
		IssuedAt: time.Now(),
		// Revoking means releasing a lease at the source, which needs a handle to
		// release. The alicloud driver's only mint path returns self-expiring STS
		// session credentials and no leaseID, so this is always false here.
		Revocable: leaseTTL > 0 && leaseID != "",
		Data:      data,
		Metadata:  meta,
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
