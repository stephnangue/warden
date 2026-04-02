package drivers

import "net/http"

import "github.com/stephnangue/warden/credential"

// Default API URLs for each provider.
const (
	DefaultAnthropicAPIURL = "https://api.anthropic.com"
	DefaultOpenAIAPIURL    = "https://api.openai.com"
	DefaultMistralAPIURL   = "https://api.mistral.ai"
	DefaultSlackAPIURL     = "https://slack.com/api"
)

// AnthropicProvider defines the Anthropic API key provider configuration.
var AnthropicProvider = APIKeyProviderConfig{
	SourceType:     credential.SourceTypeAnthropic,
	DisplayName:    "Anthropic",
	DefaultAPIURL:  DefaultAnthropicAPIURL,
	VerifyEndpoint: "/v1/models",
	VerifyMethod:   http.MethodGet,
	BuildAuthHeaders: func(apiKey string) map[string]string {
		return map[string]string{
			"x-api-key":         apiKey,
			"anthropic-version": "2023-06-01",
			"Accept":            "application/json",
		}
	},
	OptionalMetadata: []string{"organization_id"},
}

// OpenAIProvider defines the OpenAI API key provider configuration.
var OpenAIProvider = APIKeyProviderConfig{
	SourceType:     credential.SourceTypeOpenAI,
	DisplayName:    "OpenAI",
	DefaultAPIURL:  DefaultOpenAIAPIURL,
	VerifyEndpoint: "/v1/models",
	VerifyMethod:   http.MethodGet,
	BuildAuthHeaders: func(apiKey string) map[string]string {
		return map[string]string{
			"Authorization": "Bearer " + apiKey,
			"Accept":        "application/json",
		}
	},
	OptionalMetadata: []string{"organization_id", "project_id"},
}

// MistralProvider defines the Mistral API key provider configuration.
var MistralProvider = APIKeyProviderConfig{
	SourceType:     credential.SourceTypeMistral,
	DisplayName:    "Mistral",
	DefaultAPIURL:  DefaultMistralAPIURL,
	VerifyEndpoint: "/v1/models",
	VerifyMethod:   http.MethodGet,
	BuildAuthHeaders: func(apiKey string) map[string]string {
		return map[string]string{
			"Authorization": "Bearer " + apiKey,
			"Accept":        "application/json",
		}
	},
	OptionalMetadata: []string{"organization_id"},
}

// SlackProvider defines the Slack API key provider configuration.
var SlackProvider = APIKeyProviderConfig{
	SourceType:     credential.SourceTypeSlack,
	DisplayName:    "Slack",
	DefaultAPIURL:  DefaultSlackAPIURL,
	VerifyEndpoint: "/auth.test",
	VerifyMethod:   http.MethodPost,
	BuildAuthHeaders: func(apiKey string) map[string]string {
		return map[string]string{
			"Authorization": "Bearer " + apiKey,
			"Content-Type":  "application/json",
		}
	},
	OptionalMetadata: nil,
}
