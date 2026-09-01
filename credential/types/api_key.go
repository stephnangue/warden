package types

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/stephnangue/warden/credential"
)

// APIKeyCredType handles static API key credentials (OpenAI, Anthropic, Mistral, Slack, etc.)
type APIKeyCredType struct {
	*BaseTokenType
}

// NewAPIKeyCredType creates a new API key credential type
func NewAPIKeyCredType() *APIKeyCredType {
	return &APIKeyCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeAPIKey,
				Category:    credential.CategoryAPI,
				Description: "API key for provider authentication (OpenAI, Anthropic, Mistral, Slack, etc.)",
				DefaultTTL:  0, // Static API keys have no default TTL
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "api_key",
				AlternativeFields: []string{},

				// Empty by design. api_key is the only field this type owns;
				// every adjunct — an organization, a second key, an account
				// identity — is named by the operator in the source's
				// credential_fields and carried by the parser.
				//
				// A fixed list here could only hold fields anticipated when the
				// type was written, which is what left several provider
				// extractors reading credential data nothing could supply. The
				// declared route has no such ceiling: a new provider field costs
				// no change to this type.
				OptionalFields: []string{},

				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"api_key": {
						Description: "API key for authentication",
						Sensitive:   true,
					},
				},
			},
			// Revocable where a lease exists. Parse gates this on a non-empty
			// leaseID, so the sources that read a key out of a store — the apikey
			// and local specs, the vault static_apikey read, the aws
			// secrets_manager read — stay non-revocable: they hand back a key they
			// did not create and return no lease, and revoking one would destroy a
			// secret somebody else owns.
			//
			// The sources that CREATE a key upstream do return one, and every one
			// of them implements a Revoke that invalidates it. Left false, that
			// lease reached nothing: the expiration manager is only told about a
			// credential the type calls revocable, so a key minted for a caller
			// outlived the session it was minted for and sat at the upstream until
			// its own expiry — which an elastic spec may set to 30d, and which a
			// grafana service-account token does not have at all.
			Revocable: true,
		},
	}
}

// ConfigSchema returns the declarative schema for API key credential config.
// The API key is stored at the spec level (like GitHub PATs), not on the source.
func (t *APIKeyCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("api_key").
			Describe("API key for provider authentication").
			Example("sk-xxxxxxxxxxxxxxxxxxxx"),

		// Adjunct fields: everything a credential carries beyond api_key. Declaring
		// one here documents it and marks it known — which is what keeps it
		// readable, since masking treats an undeclared spec-config key as a
		// possible secret. Declaring does NOT carry it: on an apikey source a field
		// travels only when the source's credential_fields names it.
		credential.StringField("organization_id").
			Describe("Organization ID (optional)").
			Example("org-xxxxxxxxxxxx"),

		credential.StringField("project_id").
			Describe("Project ID (optional)").
			Example("proj-xxxxxxxxxxxx"),

		credential.StringField("key_id").
			Describe("Key identifier (optional; honeycomb uses it to select management-key mode)").
			Example("hcaik_xxxxxxxxxxxx"),

		credential.StringField("key_name").
			Describe("Human-readable key name (optional)").
			Example("warden-prod"),

		credential.StringField("email").
			Describe("Account identity paired with the key (optional; atlassian uses it for Basic auth)").
			Example("svc@example.com"),

		credential.StringField("application_key").
			Describe("Second API key some providers require alongside api_key (optional; datadog)").
			Example("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),

		// Mint parameters for the sources that create a key upstream rather than
		// reading one out of a store. They shape the request the driver makes;
		// none of them is part of the credential.
		//
		// Declared for the same reason as the adjuncts above: an undeclared
		// spec-config key is masked on read, since the type has no basis for
		// calling an unrecognised key public. Left undeclared, an operator reading
		// back a spec would find the indices their key is scoped to displayed as a
		// secret.
		credential.StringField("expiration").
			Describe("Key lifetime, as an Elasticsearch time value (elastic; default 1h)").
			Example("24h"),

		credential.StringField("role_descriptors").
			Describe("JSON role descriptors scoping the key's privileges (elastic)").
			Example(`{"reader":{"indices":[{"names":["logs-*"],"privileges":["read"]}]}}`),

		credential.StringField("role").
			OneOf("Viewer", "Editor", "Admin").
			Describe("Service-account role (grafana)").
			Example("Viewer"),

		credential.StringField("name_prefix").
			Describe("Prefix for the generated service-account name (grafana)").
			Example("warden"),

		credential.StringField("org_id").
			Describe("Organization the service account is created in (grafana)").
			Example("1"),

		credential.StringField("key_type").
			OneOf("ingest", "configuration").
			Describe("Which kind of key to create (honeycomb)").
			Example("ingest"),

		credential.StringField("key_name_prefix").
			Describe("Prefix for the generated key name (honeycomb)").
			Example("warden"),

		credential.StringField("environment_id").
			Describe("Environment the key is created in (honeycomb)").
			Example("hcaen_xxxxxxxxxxxx"),

		credential.StringField("permissions").
			Describe("JSON permissions for a configuration key (honeycomb)").
			Example(`{"create_datasets":true}`),

		// Store-backed sources (vault static_apikey, aws secrets_manager)
		credential.StringField("mint_method").
			OneOf("static_apikey", "secrets_manager").
			Describe("Mint method (required for vault or aws source)").
			Example("static_apikey"),

		credential.StringField("kv2_mount").
			Describe("Vault KV2 mount path (required for static_apikey)").
			Example("secret"),

		credential.StringField("secret_path").
			Describe("Path to secret in KV2 (required for static_apikey)").
			Example("apikeys/my-service"),

		// AWS source - Secrets Manager fields. The fetched secret must contain an
		// api_key field (or be remapped to one via json_key_map).
		credential.StringField("credential_type").
			OneOf(credential.TypeAPIKey).
			Describe("Selects the api_key shape for a Secrets Manager secret").
			Example(credential.TypeAPIKey),

		credential.StringField("secret_id").
			Describe("AWS Secrets Manager secret ID (required for secrets_manager)").
			Example("prod/app/openai"),

		credential.StringField("role_arn").
			Describe("IAM role ARN to assume via web identity (required for keyless secrets_manager)").
			Example("arn:aws:iam::123456789012:role/WardenSecretsReader"),

		credential.StringField("version_stage").
			Describe("Secrets Manager version stage (optional, defaults to AWSCURRENT)").
			Example("AWSCURRENT"),

		credential.StringField("version_id").
			Describe("Specific Secrets Manager version ID (optional)").
			Example("uuid-version-id"),

		// Field selection over the stored secret, shared by the KV read
		// (static_apikey) and the Secrets Manager read.
		credential.StringField("json_key_map").
			Describe("Comma-separated 'srcKey=destKey' selection of the stored secret's fields; unnamed keys are not vended. Use it when the stored key is not named api_key").
			Example("token=api_key"),

		credential.IntField("secret_version").
			Min(1).
			Describe("Pin a numbered revision of the KV secret (static_apikey only); omit to read the current one. A pinned spec does not follow rotation").
			Example("3"),

		// Credential chaining (apikey source): source the api_key from another cred spec
		// instead of storing it inline, making the spec keyless.
		credential.StringField(credential.ConfigSecretSpec).
			Describe("Name of a cred spec that yields the api_key instead of storing it inline (credential chaining)").
			Example("openai-key-in-vault"),

		credential.StringField(credential.ConfigSecretField).
			Describe("Which key of the referenced secret_spec's data holds the api_key; optional when the payload is single-key").
			Example("api_key"),

		credential.DurationField(credential.ConfigSecretCacheTTL).
			Describe("Cache the chained api_key source-wide for this duration (e.g. 30m); omit to fetch on every mint").
			Example("30m"),
	}
}

// ValidateConfig validates the Config for an API key credential spec.
// The API key is stored at the spec level (like GitHub PATs). The source only
// holds connection info (api_url). This allows multiple specs with different
// API keys to share one source.
func (t *APIKeyCredType) ValidateConfig(config map[string]string, sourceType string) error {
	// Step 1: Validate source type compatibility.
	//
	// Two families reach this type. One holds the key in the spec or reads it out
	// of a store; the other creates a fresh key at the upstream on every mint, and
	// so carries no key in the spec at all — which is why the required-api_key
	// check below is not reached for them.
	//
	// The second family was missing here, and its absence made all three of those
	// drivers unreachable: their factories infer this type, no other type accepts
	// their source, and so every spec written against one was refused. There is no
	// second path to reach them.
	switch sourceType {
	case credential.SourceTypeAPIKey, credential.SourceTypeLocal, credential.SourceTypeVault, credential.SourceTypeAWS,
		credential.SourceTypeElastic, credential.SourceTypeGrafana, credential.SourceTypeHoneycomb:
		// Supported
	default:
		return fmt.Errorf("api_key credentials require an apikey, local, vault, aws, elastic, grafana, or honeycomb source, got: %s", sourceType)
	}

	// Step 2: Validate config against schema
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Credential chaining is only meaningful for the apikey source, whose key is
	// otherwise stored inline in the spec. The other source types fetch the key from
	// their own backend (Vault KV / Secrets Manager), and local has no keyless path —
	// reject secret_spec there rather than letting it fail late at mint time.
	if config[credential.ConfigSecretSpec] != "" && sourceType != credential.SourceTypeAPIKey {
		return fmt.Errorf("secret_spec (credential chaining) is not supported with a %s source", sourceType)
	}

	// Step 3: Source-specific validation
	switch sourceType {
	case credential.SourceTypeVault:
		if config["mint_method"] != "static_apikey" {
			return fmt.Errorf("'mint_method' must be 'static_apikey' for vault source, got: %s", config["mint_method"])
		}
		if config["kv2_mount"] == "" {
			return fmt.Errorf("'kv2_mount' is required when mint_method is static_apikey")
		}
		if config["secret_path"] == "" {
			return fmt.Errorf("'secret_path' is required when mint_method is static_apikey")
		}
	case credential.SourceTypeAWS:
		// The API key is read from AWS Secrets Manager, not carried in the spec, so
		// validate the fetch config (shared with aws_access_keys) rather than requiring
		// an api_key field here. The secret's payload must contain api_key (or be
		// remapped to it via json_key_map).
		if config["mint_method"] != "secrets_manager" {
			return fmt.Errorf("'mint_method' must be 'secrets_manager' for an aws source, got: %s", config["mint_method"])
		}
		return validateAWSSecretsManagerSpecConfig(config)
	case credential.SourceTypeElastic:
		// The key is created at the cluster on every mint, so the spec carries
		// none. What it carries is the shape of the key to create.
		//
		// An expiration is checked here rather than left to the cluster because a
		// key minted without one never expires, and the driver's default is only
		// applied when the field is absent: set-but-empty reaches the cluster as
		// "no expiration". A spec that says expiration= reads as though it asked
		// for something.
		if raw, present := config["expiration"]; present {
			if err := validateElasticTimeValue(raw); err != nil {
				return fmt.Errorf("'expiration': %w", err)
			}
		}
		if rd := config["role_descriptors"]; rd != "" {
			if !json.Valid([]byte(rd)) {
				return fmt.Errorf("'role_descriptors' is not valid JSON")
			}
		}
	case credential.SourceTypeGrafana, credential.SourceTypeHoneycomb:
		// As above: the key is created upstream per mint and the spec holds no
		// key. Their mint parameters are validated by their own drivers.
	default:
		// apikey source: the api_key lives inline in the spec, unless it is sourced from
		// another cred spec via credential chaining (secret_spec) — the two are mutually
		// exclusive. (local reaches here only when secret_spec is unset; the guard above
		// rejects a chained local spec.)
		if config[credential.ConfigSecretSpec] != "" {
			if config["api_key"] != "" {
				return fmt.Errorf("'api_key' and 'secret_spec' are mutually exclusive (the key is fetched from the referenced secret_spec)")
			}
		} else if config["api_key"] == "" {
			return fmt.Errorf("'api_key' is required")
		}
	}

	return nil
}

// elasticTimeUnits are the suffixes an Elasticsearch time value may carry,
// longest first so "ms" is matched before "s" and "micros" before "s".
var elasticTimeUnits = []string{"nanos", "micros", "ms", "d", "h", "m", "s"}

// validateElasticTimeValue checks a duration written the way Elasticsearch
// writes them: an integer and a unit, no sign, no fractional part.
//
// This deliberately does not use time.ParseDuration. The two notations overlap
// enough to look interchangeable and disagree exactly where it costs: Go rejects
// "30d", the single most likely value for a key lifetime and the one the driver
// documentation uses, while accepting "1.5h" and "-1h", which the cluster does
// not.
func validateElasticTimeValue(v string) error {
	if v == "" {
		return fmt.Errorf("must not be empty; omit it to take the default, or give a lifetime such as 24h or 30d")
	}
	for _, unit := range elasticTimeUnits {
		digits, ok := strings.CutSuffix(v, unit)
		if !ok || digits == "" {
			continue
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			break
		}
		if n <= 0 {
			return fmt.Errorf("must be positive, got: %s", v)
		}
		return nil
	}
	return fmt.Errorf("is not an Elasticsearch time value (an integer and one of %s), got: %s",
		strings.Join(elasticTimeUnits, ", "), v)
}

// RequiresSpecRotation returns false — API keys live in source config, not spec.
func (t *APIKeyCredType) RequiresSpecRotation() bool {
	return false
}

// apiKeyAdjunctFields are the spec-config keys that describe the credential
// rather than the mint. Declared in ConfigSchema so they read back unmasked, and
// listed here so a spec setting one that its source will not carry is rejected
// instead of minting a credential silently missing it.
//
// A provider needing a field absent from this list still works — the operator
// names it in credential_fields and it is carried. The list only decides which
// names Warden can give a helpful error about.
var apiKeyAdjunctFields = []string{
	"organization_id", "project_id", "key_id", "key_name", "email", "application_key",
}

// KnownAdjunctFields implements credential.AdjunctCarrier.
func (t *APIKeyCredType) KnownAdjunctFields() []string { return apiKeyAdjunctFields }

// SensitiveConfigFields returns spec config keys that should be masked in output.
// The known secrets — see SensitiveConfigFieldsFor for the fields an operator adds
// that this list cannot anticipate.
func (t *APIKeyCredType) SensitiveConfigFields() []string {
	return []string{"api_key", "application_key"}
}

// SensitiveConfigFieldsFor masks the known secrets plus every spec-config key the
// type does not recognise (credential.ConfigSensitivity).
//
// An api_key spec may carry adjunct fields declared by the operator rather than by
// this type, so a fixed list cannot say which are secret. An unrecognised key is
// therefore masked: it was put there to be part of the credential, and the type
// has no basis for calling it public. Declaring a field in ConfigSchema is how it
// becomes readable — which is why the non-secret adjuncts are declared there.
//
// Reserved keys stay visible: mint locators and chaining references address the
// mint rather than describing the credential, and masking a secret_path would hide
// where a credential comes from while protecting nothing.
func (t *APIKeyCredType) SensitiveConfigFieldsFor(config map[string]string) []string {
	fields := t.SensitiveConfigFields()

	known := make(map[string]bool, len(t.ConfigSchema()))
	for _, v := range t.ConfigSchema() {
		known[v.FieldName()] = true
	}

	for key := range config {
		// Named reserved keys only. IsReservedSpecConfigKey also matches the "__"
		// prefix, which is right for carriage — those belong to the mint pipeline
		// — but wrong here: nothing rejects a spec-config key called "__whatever",
		// so exempting the prefix would leave the one shape of unknown key that
		// reads back in the clear.
		if known[key] || credential.IsReservedSpecConfigName(key) {
			continue
		}
		fields = append(fields, key)
	}
	return fields
}
