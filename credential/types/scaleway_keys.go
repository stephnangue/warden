package types

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
)

// scalewayMaxDescriptionLength bounds the description sent when minting a key.
// Enforced here rather than left to the API so an over-long value — which the
// default "warden-<spec name>" can reach on its own — is refused at spec create
// instead of failing every mint.
const scalewayMaxDescriptionLength = 200

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
			OneOf("static_keys", "dynamic_keys").
			Describe("Mint method for credential minting").
			Example("static_keys"),

		// Scaleway dynamic_keys fields
		credential.StringField("application_id").
			Describe("IAM application ID to create keys for (required for dynamic_keys)").
			Example("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),

		credential.StringField("default_project_id").
			Describe("Default project ID for Object Storage (optional)").
			Example("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"),

		credential.StringField("description").
			Custom(func(v string) error {
				if len(v) > scalewayMaxDescriptionLength {
					return fmt.Errorf("description must be at most %d characters, got %d", scalewayMaxDescriptionLength, len(v))
				}
				return nil
			}).
			Describe("Description for dynamically created keys (max 200 chars)").
			Example("warden-managed-key"),

		credential.DurationField("ttl").
			Custom(func(v string) error {
				// DurationField only checks that the value parses, so "0s" and "-1h"
				// reach the mint and produce a key that is born expired — with a lease
				// TTL of 0, which makes it unrevocable and so never cleaned up.
				d, err := time.ParseDuration(v)
				if err != nil {
					return nil // the field's own parse check reports this
				}
				if d <= 0 {
					return fmt.Errorf("ttl must be positive, got %s", v)
				}
				return nil
			}).
			Describe("TTL for dynamically created keys (default: 1h)").
			Example("1h"),
	}
}

// ValidateConfig validates the Config for a Scaleway credential spec
func (t *ScalewayKeysCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// A vault source is not supported: it would need a static_scaleway mint method,
	// which the Vault driver has never implemented. It used to be accepted here and
	// then failed at the first mint.
	switch sourceType {
	case credential.SourceTypeLocal, credential.SourceTypeScaleway:
		// Supported
	default:
		return fmt.Errorf("scaleway_keys credentials require a local or scaleway source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	switch sourceType {
	case credential.SourceTypeScaleway:
		chained := config[credential.ConfigSecretSpec] != ""
		mintMethod := config["mint_method"]
		switch mintMethod {
		case "static_keys":
			// The pair either lives here or is fetched from a referenced spec — never
			// both. A half left behind would be presented against the other half
			// fetched from the chain.
			if chained {
				for _, key := range []string{"access_key", "secret_key"} {
					if config[key] != "" {
						return fmt.Errorf("'%s' must be omitted when '%s' is set; the referenced spec supplies the whole pair",
							key, credential.ConfigSecretSpec)
					}
				}
				// secret_field names one secret, and a pair is not one: both halves are
				// read by name. Anything set here was set deliberately and does nothing.
				if config[credential.ConfigSecretField] != "" {
					return fmt.Errorf("'%s' does not apply to static_keys: the credential is a pair, read from the referenced payload's 'access_key' and 'secret_key' by name",
						credential.ConfigSecretField)
				}
				break
			}
			// Naming both remedies matters: on a chained source the missing-pair error
			// would otherwise send an operator to add inline keys that the rule above
			// then rejects.
			if config["access_key"] == "" || config["secret_key"] == "" {
				return fmt.Errorf("static_keys needs 'access_key' and 'secret_key', or a '%s' naming a spec that yields them",
					credential.ConfigSecretSpec)
			}
		case "dynamic_keys":
			// The management key authenticates the SOURCE's calls to the IAM API, and
			// the driver factory only ever sees source config — a reference parked on
			// the spec would slip past the checks that gate a chained source.
			if chained {
				return fmt.Errorf("for dynamic_keys, set '%s' on the source: the chained management key authenticates the source, not this spec",
					credential.ConfigSecretSpec)
			}
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
func (t *ScalewayKeysCredType) Parse(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	accessKey, ok := rawData["access_key"].(string)
	if !ok || accessKey == "" {
		return nil, fmt.Errorf("%w: missing or invalid access_key", credential.ErrInvalidCredential)
	}

	secretKey, ok := rawData["secret_key"].(string)
	if !ok || secretKey == "" {
		return nil, fmt.Errorf("%w: missing or invalid secret_key", credential.ErrInvalidCredential)
	}

	meta, err := helper.ToStringMap(metadata)
	if err != nil {
		return nil, err
	}

	return &credential.Credential{
		Type:     credential.TypeScalewayKeys,
		Category: credential.CategoryCloudIAM,
		LeaseTTL: leaseTTL,
		LeaseID:  leaseID,
		IssuedAt: time.Now(),
		// Revoking means releasing a lease at the source, which needs a handle to
		// release. Both conditions are load-bearing: a chained mint reports a TTL
		// bounding how long its material may be reused, but hands out no leaseID —
		// it has no key of its own to authorise a delete with, and no caller at
		// expiry to fetch one. Registering such a credential for revocation would
		// schedule a call that can only fail.
		Revocable: leaseTTL > 0 && leaseID != "",
		Data: map[string]string{
			"access_key": accessKey,
			"secret_key": secretKey,
		},
		Metadata: meta,
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
