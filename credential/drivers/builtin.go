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

	// Register static API key driver factories (Anthropic, OpenAI, Mistral, Slack, PagerDuty)
	for _, provider := range []APIKeyProviderConfig{
		AnthropicProvider, OpenAIProvider, MistralProvider, SlackProvider, PagerDutyProvider,
	} {
		if err := registry.RegisterFactory(NewStaticAPIKeyDriverFactory(provider)); err != nil {
			return err
		}
	}

	// Register OAuth2 client credentials driver factories
	for _, provider := range []OAuth2ProviderConfig{
		PagerDutyOAuth2Provider,
	} {
		if err := registry.RegisterFactory(NewOAuth2DriverFactory(provider)); err != nil {
			return err
		}
	}

	return nil
}
