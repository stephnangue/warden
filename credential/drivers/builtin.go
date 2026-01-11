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

	return nil
}
