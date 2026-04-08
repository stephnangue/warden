package types

import (
	"fmt"
	"time"

	"github.com/stephnangue/warden/credential"
)

// KubernetesTokenCredType handles Kubernetes ServiceAccount tokens
// created via the TokenRequest API.
type KubernetesTokenCredType struct {
	*BaseTokenType
}

// NewKubernetesTokenCredType creates a new Kubernetes token credential type
func NewKubernetesTokenCredType() *KubernetesTokenCredType {
	return &KubernetesTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeKubernetesToken,
				Category:    credential.CategoryK8s,
				Description: "Kubernetes ServiceAccount token for API server authentication",
				DefaultTTL:  1 * time.Hour,
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "token",
				AlternativeFields: []string{},
				OptionalFields:    []string{"namespace", "service_account", "audiences"},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"token": {
						Description: "Kubernetes ServiceAccount bearer token",
						Sensitive:   true,
					},
					"namespace": {
						Description: "Kubernetes namespace of the service account",
						Sensitive:   false,
					},
					"service_account": {
						Description: "Name of the service account",
						Sensitive:   false,
					},
					"audiences": {
						Description: "Comma-separated token audiences",
						Sensitive:   false,
					},
				},
			},
			Revocable: false, // SA tokens expire naturally and cannot be revoked
		},
	}
}

// ConfigSchema returns the declarative schema for Kubernetes token credential config
func (t *KubernetesTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("service_account").
			Required().
			Describe("Target Kubernetes service account name").
			Example("my-app-sa"),

		credential.StringField("namespace").
			Required().
			Describe("Kubernetes namespace of the target service account").
			Example("default"),

		credential.StringField("audiences").
			Describe("Comma-separated list of token audiences").
			Example("https://my-app.example.com"),

		credential.DurationField("ttl").
			Describe("Token TTL (default: 1h, min: 10m, max: 48h)").
			Example("1h"),
	}
}

// ValidateConfig validates the Config for a Kubernetes token credential spec
func (t *KubernetesTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	if sourceType != credential.SourceTypeKubernetes {
		return fmt.Errorf("kubernetes_token credentials require a kubernetes source, got: %s", sourceType)
	}

	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	// Validate TTL range if provided
	if ttlStr, ok := config["ttl"]; ok && ttlStr != "" {
		ttl, err := time.ParseDuration(ttlStr)
		if err != nil {
			return fmt.Errorf("invalid ttl: %w", err)
		}
		if ttl < 10*time.Minute {
			return fmt.Errorf("ttl must be at least 10m, got: %s", ttl)
		}
		if ttl > 48*time.Hour {
			return fmt.Errorf("ttl must not exceed 48h, got: %s", ttl)
		}
	}

	return nil
}

// RequiresSpecRotation indicates that Kubernetes token specs do NOT embed
// per-spec credentials. Tokens are minted fresh each time.
func (t *KubernetesTokenCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *KubernetesTokenCredType) SensitiveConfigFields() []string {
	return []string{}
}
