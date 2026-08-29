package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
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
		credential.StringField("mint_method").
			OneOf("oauth2_token", "access_keys").
			Describe("Mint method for credential minting").
			Example("oauth2_token"),
	}
}

// ValidateConfig validates the Config for an OVH credential spec
func (t *OVHKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	if sourceType != credential.SourceTypeOVH {
		return fmt.Errorf("ovh_keys credentials require an ovh source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	mintMethod := config["mint_method"]
	switch mintMethod {
	case "oauth2_token":
		// The grant runs with the source's service account, so a reference parked
		// here would describe a secret this spec never spends — and would slip past
		// the source-level checks that gate which sources may chain at all.
		if config[credential.ConfigSecretSpec] != "" {
			return fmt.Errorf("for an oauth2_token spec, '%s' belongs on the source: the client credential authenticates the source's own OAuth2 calls, not this spec", credential.ConfigSecretSpec)
		}

	case "access_keys":
		// The pair is the credential itself, so the spec must name where it comes
		// from. Nothing mints it: this method exists precisely so that no key pair
		// is created — and therefore left behind — on OVH's side.
		if config[credential.ConfigSecretSpec] == "" {
			return fmt.Errorf("'access_keys' requires '%s' naming a spec that yields its access_key and secret_key", credential.ConfigSecretSpec)
		}
		// Refuse an inline pair rather than quietly preferring one over the other:
		// a key pair sitting in spec config is the standing secret this method
		// exists to avoid, and nothing here would ever rotate it.
		for _, key := range []string{"access_key", "secret_key"} {
			if config[key] != "" {
				return fmt.Errorf("'%s' must be omitted for access_keys; the referenced spec supplies the whole pair", key)
			}
		}
		// secret_field selects a single secret, and a pair is not one. Both halves
		// are read by name, so a field here could only be misleading.
		if config[credential.ConfigSecretField] != "" {
			return fmt.Errorf("'%s' does not apply to access_keys: the referenced credential must hold both 'access_key' and 'secret_key', read by name", credential.ConfigSecretField)
		}

	default:
		return fmt.Errorf("'mint_method' must be 'oauth2_token' or 'access_keys', got: %s", mintMethod)
	}

	return nil
}

// Parse converts raw credential data from source into structured Credential
func (t *OVHKeysCredType) Parse(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	accessKey, _ := rawData["access_key"].(string)
	secretKey, _ := rawData["secret_key"].(string)
	apiToken, _ := rawData["api_token"].(string)

	// S3 mode fields must come as a pair
	if (accessKey != "") != (secretKey != "") {
		if accessKey == "" {
			return nil, fmt.Errorf("%w: access_key is required when secret_key is provided", credential.ErrInvalidCredential)
		}
		return nil, fmt.Errorf("%w: secret_key is required when access_key is provided", credential.ErrInvalidCredential)
	}

	hasS3 := accessKey != "" && secretKey != ""
	hasAPI := apiToken != ""

	// At least one complete mode required
	if !hasS3 && !hasAPI {
		return nil, fmt.Errorf("%w: at least one mode is required: api_token for API mode, or access_key + secret_key for S3 mode", credential.ErrInvalidCredential)
	}

	data := make(map[string]string)
	if hasS3 {
		data["access_key"] = accessKey
		data["secret_key"] = secretKey
	}
	if hasAPI {
		data["api_token"] = apiToken
	}

	meta, err := helper.ToStringMap(metadata)
	if err != nil {
		return nil, err
	}

	return &credential.Credential{
		Type:     credential.TypeOVHKeys,
		Category: credential.CategoryCloudIAM,
		LeaseTTL: leaseTTL,
		LeaseID:  leaseID,
		IssuedAt: time.Now(),
		// Revoking means releasing a lease at the source, which needs a handle to
		// release. No OVH mint method returns one: a bearer token expires on its
		// own, and an access_keys pair was never created here to be deleted. The
		// condition stays because the field is what the rest of the system reads.
		Revocable: leaseTTL > 0 && leaseID != "",
		Data:      data,
		Metadata:  meta,
	}, nil
}

// Validate checks if credential data is well-formed
func (t *OVHKeysCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeOVHKeys {
		return fmt.Errorf("%w: expected type %s, got %s", credential.ErrInvalidCredential, credential.TypeOVHKeys, cred.Type)
	}

	hasAccessKey := cred.Data["access_key"] != ""
	hasSecretKey := cred.Data["secret_key"] != ""
	hasAPIToken := cred.Data["api_token"] != ""

	// S3 mode fields must come as a pair
	if hasAccessKey != hasSecretKey {
		if !hasAccessKey {
			return fmt.Errorf("%w: missing access_key (required when secret_key is present)", credential.ErrInvalidCredential)
		}
		return fmt.Errorf("%w: missing secret_key (required when access_key is present)", credential.ErrInvalidCredential)
	}

	hasS3 := hasAccessKey && hasSecretKey

	if !hasS3 && !hasAPIToken {
		return fmt.Errorf("%w: at least one mode is required: api_token or access_key + secret_key", credential.ErrInvalidCredential)
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
	return nil
}

// FieldSchemas returns metadata about the credential's data fields
func (t *OVHKeysCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema {
	return map[string]*credential.CredentialFieldSchema{
		"access_key": {
			Description: "OVH S3 access key (required for S3 mode, optional if only using API mode)",
			Sensitive:   false,
		},
		"secret_key": {
			Description: "OVH S3 secret key (required for S3 mode, optional if only using API mode)",
			Sensitive:   true,
		},
		"api_token": {
			Description: "OVH API bearer token (required for API mode, optional if only using S3 mode)",
			Sensitive:   true,
		},
	}
}
