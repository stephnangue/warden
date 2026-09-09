package types

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/helper"
)

// KeyValueCredType is a generic, structure-agnostic credential type: its Data is
// the arbitrary key/value map the source returned, with no required primary field.
// It lets a referenced "secret spec" (credential chaining) carry secret material
// under its natural key names instead of being forced into a typed shape like
// api_key.
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
		Description: "Generic key/value secret material with arbitrary fields, read from a store that holds it under its own key names",
		DefaultTTL:  0, // static read, no default TTL
	}
}

// ConfigSchema returns the declarative schema for key/value credential config.
// (Unknown keys such as exchange config are ignored by ValidateSchema and validated
// elsewhere, so they need not be listed here.)
func (t *KeyValueCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("mint_method").
			OneOf("kv2_read", "transit_signer", "secret_read").
			Describe("Mint method: kv2_read reads a KV v2 secret and transit_signer mints a scoped signing capability, both on an hvault source; secret_read reads a stored secret on an aws source").
			Example("kv2_read"),

		credential.StringField("kv2_mount").
			Describe("KV v2 mount path (hvault source)").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to the secret within the KV v2 mount (hvault source). Supports {{user.<claim>}} and {{agent.<claim>}} templating").
			Example("github/ci"),

		credential.StringField("secret_id").
			Describe("Stored secret to read, by name or ARN (aws source, required for secret_read). Supports {{user.<claim>}} and {{agent.<claim>}} templating").
			Example("prod/datadog/keys"),

		credential.StringField("version_stage").
			Describe("Staging label of the revision to read (aws source; default AWSCURRENT)").
			Example("AWSCURRENT"),

		credential.StringField("version_id").
			Describe("Pin an exact revision by id (aws source); omit to read the staged one").
			Example("b3028f1a-1c2d-4e5f-8a9b-0c1d2e3f4a5b"),

		credential.StringField("role_arn").
			Describe("IAM role to assume via web identity (aws source, required when the spec sets subject_token_source)").
			Example("arn:aws:iam::123456789012:role/WardenSecretsReader"),

		credential.StringField("session_name").
			Describe("Session name for the assumed role (aws source; defaults to warden-<spec name>)").
			Example("warden-datadog-keys"),

		credential.StringField("policy").
			Describe("Inline IAM policy further restricting the assumed role (aws source)").
			Example(""),

		credential.StringField("json_key_map").
			Describe("Comma-separated 'srcKey=destKey' selection of the stored secret's fields; unnamed keys are not vended. Omit to vend the payload verbatim").
			Example("token=api_key"),

		credential.IntField("secret_version").
			Min(1).
			Describe("Pin a numbered revision of the secret; omit to read the current one. A pinned spec does not follow rotation").
			Example("3"),
	}
}

// Each source's mint methods read their own locator keys, and a spec carrying the
// other source's is rejected by name. The schema ignores keys it does not know, so
// such a key would be accepted and then never read — leaving a spec that reads as
// configured for something it is not doing.
//
// secret_version is deliberately absent from the hvault list even though only that
// source honours it: ValidateSecretSelection already rejects it everywhere else,
// and one mistake with two error messages is two messages that drift.
var (
	vaultKeyValueLocators = []string{
		"kv2_mount", "secret_path", // kv2_read
		"transit_key", "transit_key_version", "transit_mount", "signing_alg", "jwt_role", // transit_signer
	}
	awsKeyValueLocators = []string{
		"secret_id", "version_stage", "version_id", "role_arn", "session_name", "policy",
	}
)

// ValidateConfig validates the Config for a key/value credential spec. Two source
// types produce this shape: an hvault source reading KV v2 or minting a signing
// capability, and an aws source reading a stored secret.
func (t *KeyValueCredType) ValidateConfig(config credential.Config, sourceType string) error {
	switch sourceType {
	case credential.SourceTypeVault, credential.SourceTypeAWS:
		// Supported
	default:
		return fmt.Errorf("key_value credentials require an hvault or aws source, got: %s", sourceType)
	}

	if err := credential.ValidateSchema(config, t.ConfigSchema()...); err != nil {
		return err
	}

	switch sourceType {
	case credential.SourceTypeVault:
		return t.validateVaultConfig(config)
	default:
		return t.validateAWSConfig(config)
	}
}

// validateVaultConfig checks the two mint methods an hvault source offers for this
// type. Both produce a multi-field payload with no primary field, which is what this
// type exists to carry. What they need from the config differs entirely, so each
// states its own requirements; the driver checks the rest against the store, where a
// locator can actually be resolved.
func (t *KeyValueCredType) validateVaultConfig(config credential.Config) error {
	switch config.Get("mint_method") {
	case "kv2_read":
		if config.Get("kv2_mount") == "" {
			return fmt.Errorf("'kv2_mount' is required for mint_method=kv2_read")
		}
		if config.Get("secret_path") == "" {
			return fmt.Errorf("'secret_path' is required for mint_method=kv2_read")
		}
	case "transit_signer":
		if config.Get("transit_key") == "" {
			return fmt.Errorf("'transit_key' is required for mint_method=transit_signer")
		}
		// Checked here as well as at mint time so the mistake surfaces when the spec is
		// written, rather than on the first request that needs it. A spec without its
		// own role would otherwise inherit the source's, which is the one thing this
		// mint method must never do.
		if config.Get("jwt_role") == "" {
			return fmt.Errorf("'jwt_role' is required for mint_method=transit_signer: it must name a role whose policy grants only signing with the key, and inheriting the source's role would grant more")
		}
	default:
		return fmt.Errorf("'mint_method' must be 'kv2_read' or 'transit_signer' for a key_value credential on an hvault source, got: %s", config.Get("mint_method"))
	}

	return rejectForeignLocators(config, awsKeyValueLocators, config.Get("mint_method"))
}

// validateAWSConfig checks the single mint method an aws source offers for this
// type: a stored-secret read whose payload is vended under its own key names.
func (t *KeyValueCredType) validateAWSConfig(config credential.Config) error {
	if config.Get("mint_method") != "secret_read" {
		return fmt.Errorf("'mint_method' must be 'secret_read' for a key_value credential on an aws source, got: %s", config.Get("mint_method"))
	}
	if err := rejectForeignLocators(config, vaultKeyValueLocators, "secret_read"); err != nil {
		return err
	}
	if err := rejectForeignPrefixes(config, vaultKeyValuePrefixes, "secret_read"); err != nil {
		return err
	}
	// credential_type selects which shape a stored secret is parsed into, which only
	// the secrets_manager method offers. This one vends the payload verbatim, so
	// there is nothing to select. The driver refuses it too, but only when the
	// operator omits `type` and leaves it to be inferred.
	if config.Get("credential_type") != "" {
		return fmt.Errorf("'credential_type' does not apply to mint_method=secret_read: the payload is vended under its own key names")
	}
	return validateAWSSecretsManagerSpecConfig(config, "secret_read")
}

// vaultKeyValuePrefixes are whole families of keys one source's mint methods read,
// which cannot be listed individually because the operator names them.
var vaultKeyValuePrefixes = []string{"payload."}

// rejectForeignLocators refuses config keys belonging to a different source's mint
// methods, which would be accepted and then never read.
func rejectForeignLocators(config credential.Config, foreign []string, mintMethod string) error {
	for _, key := range foreign {
		if config.Get(key) != "" {
			return fmt.Errorf("'%s' does not apply to mint_method=%s", key, mintMethod)
		}
	}
	return nil
}

// rejectForeignPrefixes is the same for a passthrough bag, whose keys are named by
// the operator and so cannot be enumerated.
func rejectForeignPrefixes(config credential.Config, prefixes []string, mintMethod string) error {
	for key := range config.All() {
		for _, prefix := range prefixes {
			if strings.HasPrefix(key, prefix) {
				return fmt.Errorf("'%s' does not apply to mint_method=%s", key, mintMethod)
			}
		}
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
// in persisted spec config (every key here is a non-secret locator).
func (t *KeyValueCredType) SensitiveConfigFields() []string { return nil }

// FieldSchemas returns nil — the field set is arbitrary and unknown at type level.
func (t *KeyValueCredType) FieldSchemas() map[string]*credential.CredentialFieldSchema { return nil }
