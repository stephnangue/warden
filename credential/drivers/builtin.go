package drivers

import "github.com/stephnangue/warden/credential"

// RegisterBuiltinDrivers registers all built-in driver factories
func RegisterBuiltinDrivers(registry *credential.DriverRegistry) error {
	// Register local driver factory
	if err := registry.RegisterFactory(&LocalDriverFactory{}); err != nil {
		return err
	}

	// Register Vault driver factory
	if err := registry.RegisterFactory(&VaultDriverFactory{}); err != nil {
		return err
	}

	// Register AWS driver factory
	if err := registry.RegisterFactory(&AWSDriverFactory{}); err != nil {
		return err
	}

	// Register Azure driver factory
	if err := registry.RegisterFactory(&AzureDriverFactory{}); err != nil {
		return err
	}

	return nil
}
