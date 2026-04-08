package types

import "github.com/stephnangue/warden/credential"

// RegisterBuiltinTypes registers all built-in credential types
func RegisterBuiltinTypes(registry *credential.TypeRegistry) error {
	// Register AWS IAM access keys type
	if err := registry.Register(&AWSIAMAccessKeysCredType{}); err != nil {
		return err
	}

	// Register Vault token type
	if err := registry.Register(NewVaultTokenCredType()); err != nil {
		return err
	}

	// Register Azure Bearer token type
	if err := registry.Register(NewAzureBearerTokenCredType()); err != nil {
		return err
	}

	// Register GCP access token type
	if err := registry.Register(NewGCPAccessTokenCredType()); err != nil {
		return err
	}

	// Register GitLab access token type
	if err := registry.Register(NewGitLabAccessTokenCredType()); err != nil {
		return err
	}

	// Register GitHub token type
	if err := registry.Register(NewGitHubTokenCredType()); err != nil {
		return err
	}

	// Register API key type
	if err := registry.Register(NewAPIKeyCredType()); err != nil {
		return err
	}

	// Register OAuth bearer token type
	if err := registry.Register(NewOAuthBearerTokenCredType()); err != nil {
		return err
	}

	// Register database auth token type
	if err := registry.Register(NewDBAuthTokenCredType()); err != nil {
		return err
	}

	// Register Kubernetes token type
	if err := registry.Register(NewKubernetesTokenCredType()); err != nil {
		return err
	}

	return nil
}
