package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// IBMCloudKeysCredType handles IBM Cloud credentials.
// A single credential holds an IAM bearer token for the REST API and
// S3-compatible access_key_id + secret_access_key for Cloud Object Storage (SigV4).
type IBMCloudKeysCredType struct{}

// Metadata returns the type's metadata
func (t *IBMCloudKeysCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeIBMCloudKeys,
		Category:    credential.CategoryCloudIAM,
		Description: "IBM Cloud keys (access_token for REST API, access_key_id + secret_access_key for COS Object Storage)",
		DefaultTTL:  0,
	}
}

// ConfigSchema returns the declarative schema for IBM Cloud key credential config
func (t *IBMCloudKeysCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("access_key_id").
			Describe("IBM COS HMAC access key ID").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("secret_access_key").
			Describe("IBM COS HMAC secret access key").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		credential.StringField("access_token").
			Describe("IBM Cloud IAM bearer token for REST API").
			Example("eyJraWQiOiIyMDI..."),

		credential.StringField("mint_method").
			OneOf("iam_with_cos", "dynamic_ibm").
			Describe("Mint method for credential minting").
			Example("iam_with_cos"),

		// Dynamic IBM fields (for Vault IBM secrets engine)
		credential.StringField("ibm_mount").
			Describe("Vault IBM secrets engine mount path (required for dynamic_ibm)").
			Example("ibmcloud"),

		credential.StringField("role_name").
			Describe("Vault IBM secrets engine role name (required for dynamic_ibm)").
			Example("my-role"),

		credential.StringField("iam_endpoint").
			Describe("IBM Cloud IAM endpoint (optional, defaults to https://iam.cloud.ibm.com)").
			Example("https://iam.cloud.ibm.com"),
	}
}

// ValidateConfig validates the Config for an IBM Cloud credential spec
func (t *IBMCloudKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeVault, credential.SourceTypeIBM:
		// Supported
	default:
		return fmt.Errorf("ibmcloud_keys credentials require a vault or ibm source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	switch sourceType {
	case credential.SourceTypeVault:
		if config["mint_method"] != "dynamic_ibm" {
			return fmt.Errorf("'mint_method' must be 'dynamic_ibm' for vault source, got: %s", config["mint_method"])
		}
		if config["ibm_mount"] == "" {
			return fmt.Errorf("'ibm_mount' is required when mint_method is dynamic_ibm")
		}
		if config["role_name"] == "" {
			return fmt.Errorf("'role_name' is required when mint_method is dynamic_ibm")
		}
	case credential.SourceTypeIBM:
		if config["mint_method"] != "iam_with_cos" && config["mint_method"] != "" {
			return fmt.Errorf("'mint_method' must be 'iam_with_cos' for ibm source, got: %s", config["mint_method"])
		}
		// COS HMAC keys are optional — API-only mode is valid
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
// At least one mode must be present: access_token (API) or access_key_id+secret_access_key (COS).
func (t *IBMCloudKeysCredType) Parse(rawData map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	accessKeyID, _ := rawData["access_key_id"].(string)
	secretAccessKey, _ := rawData["secret_access_key"].(string)
	accessToken, _ := rawData["access_token"].(string)

	// Partial COS credentials are invalid
	if (accessKeyID != "" && secretAccessKey == "") || (accessKeyID == "" && secretAccessKey != "") {
		return nil, fmt.Errorf("%w: both access_key_id and secret_access_key are required for COS", credential.ErrInvalidCredential)
	}

	hasAPI := accessToken != ""
	hasCOS := accessKeyID != "" && secretAccessKey != ""

	if !hasAPI && !hasCOS {
		return nil, fmt.Errorf("%w: at least one of access_token or access_key_id+secret_access_key is required", credential.ErrInvalidCredential)
	}

	data := make(map[string]string)
	if accessToken != "" {
		data["access_token"] = accessToken
	}
	if accessKeyID != "" {
		data["access_key_id"] = accessKeyID
	}
	if secretAccessKey != "" {
		data["secret_access_key"] = secretAccessKey
	}

	return &credential.Credential{
		Type:      credential.TypeIBMCloudKeys,
		Category:  credential.CategoryCloudIAM,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: leaseTTL > 0,
		Data:      data,
	}, nil
}

// Validate checks if credential data is well-formed.
// At least one mode must be present: access_token (API) or access_key_id+secret_access_key (COS).
func (t *IBMCloudKeysCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeIBMCloudKeys {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeIBMCloudKeys, cred.Type)
	}

	// Partial COS credentials are invalid
	if (cred.Data["access_key_id"] != "" && cred.Data["secret_access_key"] == "") ||
		(cred.Data["access_key_id"] == "" && cred.Data["secret_access_key"] != "") {
		return fmt.Errorf("%w: both access_key_id and secret_access_key are required for COS", credential.ErrInvalidCredential)
	}

	hasAPI := cred.Data["access_token"] != ""
	hasCOS := cred.Data["access_key_id"] != "" && cred.Data["secret_access_key"] != ""

	if !hasAPI && !hasCOS {
		return fmt.Errorf("%w: at least one of access_token or access_key_id+secret_access_key is required", credential.ErrInvalidCredential)
	}

	return nil
}

// Revoke releases the credential (best-effort).
// Revocation is delegated to the SourceDriver when a LeaseID is present.
func (t *IBMCloudKeysCredType) Revoke(ctx context.Context, cred *credential.Credential, driver credential.SourceDriver) error {
	if cred.LeaseID == "" {
		return nil
	}
	if err := driver.Revoke(ctx, cred.LeaseID); err != nil {
		return fmt.Errorf("%w: %v", credential.ErrRevocationFailed, err)
	}
	return nil
}

// RequiresSpecRotation returns false — IBM Cloud keys don't embed rotatable credentials in spec config
func (t *IBMCloudKeysCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *IBMCloudKeysCredType) SensitiveConfigFields() []string {
	return []string{"secret_access_key", "access_token"}
}

// FieldSchemas returns metadata about the credential's data fields
func (t *IBMCloudKeysCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"access_key_id": {
			Description: "IBM COS HMAC access key ID",
			Sensitive:   false,
		},
		"secret_access_key": {
			Description: "IBM COS HMAC secret access key",
			Sensitive:   true,
		},
		"access_token": {
			Description: "IBM Cloud IAM bearer token",
			Sensitive:   true,
		},
	}
}
