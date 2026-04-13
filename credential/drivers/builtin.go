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

	// Register GCP driver factory
	if err := registry.RegisterFactory(&GCPDriverFactory{}); err != nil {
		return err
	}

	// Register GitLab driver factory
	if err := registry.RegisterFactory(&GitLabDriverFactory{}); err != nil {
		return err
	}

	// Register GitHub driver factory
	if err := registry.RegisterFactory(&GitHubDriverFactory{}); err != nil {
		return err
	}

	// Register generic static API key driver factory
	if err := registry.RegisterFactory(&StaticAPIKeyDriverFactory{}); err != nil {
		return err
	}

	// Register generic OAuth2 client credentials driver factory
	if err := registry.RegisterFactory(&OAuth2DriverFactory{}); err != nil {
		return err
	}

	// Register IBM Cloud driver factory
	if err := registry.RegisterFactory(&IBMDriverFactory{}); err != nil {
		return err
	}

	// Register Elasticsearch driver factory
	if err := registry.RegisterFactory(&ElasticDriverFactory{}); err != nil {
		return err
	}

	// Register Kubernetes driver factory
	if err := registry.RegisterFactory(&KubernetesDriverFactory{}); err != nil {
		return err
	}

	// Register Scaleway driver factory
	if err := registry.RegisterFactory(&ScalewayDriverFactory{}); err != nil {
		return err
	}

	// Register OVH driver factory
	if err := registry.RegisterFactory(&OVHDriverFactory{}); err != nil {
		return err
	}

	return nil
}
