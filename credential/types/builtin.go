package types

import "github.com/stephnangue/warden/credential"

// RegisterBuiltinTypes registers all built-in credential types
func RegisterBuiltinTypes(registry *credential.TypeRegistry) error {
	// Register database username/password type
	if err := registry.Register(&DatabaseUserPassCredType{}); err != nil {
		return err
	}

	// Register AWS IAM access keys type
	if err := registry.Register(&AWSIAMAccessKeysCredType{}); err != nil {
		return err
	}

	// Register Vault token type
	if err := registry.Register(&VaultTokenCredType{}); err != nil {
		return err
	}

	// Register Azure Bearer token type
	if err := registry.Register(&AzureBearerTokenCredType{}); err != nil {
		return err
	}

	return nil
}
