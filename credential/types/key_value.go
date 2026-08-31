package types

import (
	"context"
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
)

// KeyValueCredType is a generic, structure-agnostic credential type: its Data is
// the arbitrary key/value map returned by the source (e.g. a Vault KV v2 read via
// mint_method=kv2_read), with no required primary field. It lets a referenced
// "secret spec" (credential chaining) carry secret material under its natural key
// names instead of being forced into a typed shape like api_key.
//
// It deliberately does NOT embed BaseTokenType: that base requires a primary field
// and copies only the primary + listed optional fields, dropping every other key —
// which would discard the arbitrary payload this type exists to preserve.
type KeyValueCredType struct{}

// NewKeyValueCredType creates a new key/value credential type.
func NewKeyValueCredType() *KeyValueCredType { return &KeyValueCredType{} }

// Metadata returns the type's metadata.
func (t *KeyValueCredType) Metadata() credential.TypeMetadata {
	return credential.TypeMetadata{
		Name:        credential.TypeKeyValue,
		Category:    credential.CategoryAPI,
		Description: "Generic key/value secret material with arbitrary fields (e.g. a Vault KV v2 read via mint_method=kv2_read)",
		DefaultTTL:  0, // static read, no default TTL
	}
}

// ConfigSchema returns the declarative schema for key/value credential config.
// (Unknown keys such as exchange config are ignored by ValidateSchema and validated
// elsewhere, so they need not be listed here.)
func (t *KeyValueCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("mint_method").
			OneOf("kv2_read", "transit_signer").
			Describe("Mint method (kv2_read reads a Vault KV v2 secret; transit_signer mints a scoped signing capability)").
			Example("kv2_read"),

		credential.StringField("kv2_mount").
			Describe("Vault KV v2 mount path").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to the secret within the KV v2 mount").
			Example("github/ci"),

		credential.StringField("json_key_map").
			Describe("Comma-separated 'srcKey=destKey' selection of the stored secret's fields; unnamed keys are not vended. Omit to vend the payload verbatim").
			Example("token=api_key"),

		credential.IntField("secret_version").
			Min(1).
			Describe("Pin a numbered revision of the secret; omit to read the current one. A pinned spec does not follow rotation").
			Example("3"),
	}
}

// ValidateConfig validates the Config for a key/value credential spec. Only an
// hvault source is supported (the KV v2 read lives on the Vault driver).
func (t *KeyValueCredType) ValidateConfig(config map[string]string, sourceType string) error {
	if sourceType != credential.SourceTypeVault {
		return fmt.Errorf("key_value credentials require an hvault source, got: %s", sourceType)
	}

	if err := credential.ValidateSchema(config, t.ConfigSchema()...); err != nil {
		return err
	}

	// Both mint methods produce a multi-field payload with no primary field, which is
	// what this type exists to carry. What they need from the config differs entirely,
	// so each states its own requirements; the driver checks the rest against the
	// store, where a locator can actually be resolved.
	switch config["mint_method"] {
	case "kv2_read":
		if config["kv2_mount"] == "" {
			return fmt.Errorf("'kv2_mount' is required for mint_method=kv2_read")
		}
		if config["secret_path"] == "" {
			return fmt.Errorf("'secret_path' is required for mint_method=kv2_read")
		}
	case "transit_signer":
		if config["transit_key"] == "" {
			return fmt.Errorf("'transit_key' is required for mint_method=transit_signer")
		}
		// Checked here as well as at mint time so the mistake surfaces when the spec is
		// written, rather than on the first request that needs it. A spec without its
		// own role would otherwise inherit the source's, which is the one thing this
		// mint method must never do.
		if config["jwt_role"] == "" {
			return fmt.Errorf("'jwt_role' is required for mint_method=transit_signer: it must name a role whose policy grants only signing with the key, and inheriting the source's role would grant more")
		}
	default:
		return fmt.Errorf("'mint_method' must be 'kv2_read' or 'transit_signer' for a key_value credential, got: %s", config["mint_method"])
	}

	return nil
}

// Parse copies ALL string-valued keys from rawData into the credential Data
// (lenient — unlike BaseTokenType, which keeps only the primary + optional fields).
func (t *KeyValueCredType) Parse(rawData, metadata map[string]interface{}, leaseTTL time.Duration, leaseID string) (*credential.Credential, error) {
	if len(rawData) == 0 {
		return nil, fmt.Errorf("%w: key_value credential has no data", credential.ErrInvalidCredential)
	}

	data := make(map[string]string, len(rawData))
	for k, v := range rawData {
		if s, ok := v.(string); ok {
			data[k] = s
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: key_value credential has no string-valued fields", credential.ErrInvalidCredential)
	}

	meta, err := helper.ToStringMap(metadata)
	if err != nil {
		return nil, err
	}

	return &credential.Credential{
		Type:      credential.TypeKeyValue,
		Category:  credential.CategoryAPI,
		LeaseTTL:  leaseTTL,
		LeaseID:   leaseID,
		IssuedAt:  time.Now(),
		Revocable: false,
		Data:      data,
		Metadata:  meta,
	}, nil
}

// Validate is lenient: any non-empty Data map is well-formed (no required field).
func (t *KeyValueCredType) Validate(cred *credential.Credential) error {
	if cred.Type != credential.TypeKeyValue {
		return fmt.Errorf("%w: expected type %s, got %s",
			credential.ErrInvalidCredential, credential.TypeKeyValue, cred.Type)
	}
	if len(cred.Data) == 0 {
		return fmt.Errorf("%w: key_value credential has no data", credential.ErrInvalidCredential)
	}
	return nil
}

// Revoke is a no-op — a KV read holds no lease.
func (t *KeyValueCredType) Revoke(_ context.Context, _ *credential.Credential, _ credential.SourceDriver) error {
	return nil
}

// RequiresSpecRotation returns false — the secret lives in the backend, not the spec.
func (t *KeyValueCredType) RequiresSpecRotation() bool { return false }

// SensitiveConfigFields returns nil — the secret lives only in minted Data, never
// in persisted spec config (kv2_mount/secret_path are non-secret locators).
func (t *KeyValueCredType) SensitiveConfigFields() []string { return nil }

// FieldSchemas returns nil — the field set is arbitrary and unknown at type level.
func (t *KeyValueCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema { return nil }
