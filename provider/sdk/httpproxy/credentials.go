package httpproxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/logical"
)

// CredentialExtractor extracts provider-specific credentials from a request and returns
// a map of header-name -> header-value pairs to inject into the proxied request.
type CredentialExtractor func(req *logical.Request) (map[string]string, error)

// BearerAPIKeyExtractor extracts api_key from a TypeAPIKey credential
// and injects it as Authorization: Bearer.
// Used by: OpenAI, Mistral, Slack, and similar providers.
func BearerAPIKeyExtractor(req *logical.Request) (map[string]string, error) {
	if req.Credential == nil {
		return nil, fmt.Errorf("no credential available")
	}
	if req.Credential.Type != credential.TypeAPIKey {
		return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
	}
	apiKey := req.Credential.Data["api_key"]
	if apiKey == "" {
		return nil, fmt.Errorf("credential missing api_key field")
	}
	return map[string]string{
		"Authorization": "Bearer " + apiKey,
	}, nil
}

// HeaderAPIKeyExtractor creates an extractor that injects api_key into a custom header.
// Used by: Anthropic (x-api-key header).
func HeaderAPIKeyExtractor(headerName string) CredentialExtractor {
	return func(req *logical.Request) (map[string]string, error) {
		if req.Credential == nil {
			return nil, fmt.Errorf("no credential available")
		}
		if req.Credential.Type != credential.TypeAPIKey {
			return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
		}
		apiKey := req.Credential.Data["api_key"]
		if apiKey == "" {
			return nil, fmt.Errorf("credential missing api_key field")
		}
		return map[string]string{
			headerName: apiKey,
		}, nil
	}
}

// MultiFieldAPIKeyExtractor creates an extractor that pulls multiple fields from
// a TypeAPIKey credential and maps them to headers. requiredFields must have at
// least one entry; optionalFields may be empty.
// Used by: OpenAI (api_key -> Authorization: Bearer, organization_id, project_id).
func MultiFieldAPIKeyExtractor(requiredFields map[string]string, optionalFields map[string]string) CredentialExtractor {
	return func(req *logical.Request) (map[string]string, error) {
		if req.Credential == nil {
			return nil, fmt.Errorf("no credential available")
		}
		if req.Credential.Type != credential.TypeAPIKey {
			return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
		}
		headers := make(map[string]string, len(requiredFields)+len(optionalFields))
		for credField, headerName := range requiredFields {
			val := req.Credential.Data[credField]
			if val == "" {
				return nil, fmt.Errorf("credential missing %s field", credField)
			}
			headers[headerName] = val
		}
		for credField, headerName := range optionalFields {
			if val := req.Credential.Data[credField]; val != "" {
				headers[headerName] = val
			}
		}
		return headers, nil
	}
}

// TypedTokenExtractor creates an extractor for non-APIKey credential types
// (e.g., TypeGitHubToken, TypeGitLabAccessToken). It validates the credential type,
// extracts a single field, and injects it with the given header prefix.
// Used by: GitHub (token -> "token {val}"), GitLab (access_token -> "Bearer {val}").
func TypedTokenExtractor(credType string, credField string, headerName string, headerPrefix string) CredentialExtractor {
	return func(req *logical.Request) (map[string]string, error) {
		if req.Credential == nil {
			return nil, fmt.Errorf("no credential available")
		}
		if req.Credential.Type != credType {
			return nil, fmt.Errorf("unsupported credential type: %s", req.Credential.Type)
		}
		val := req.Credential.Data[credField]
		if val == "" {
			return nil, fmt.Errorf("credential missing %s field", credField)
		}
		headerVal := val
		if headerPrefix != "" {
			headerVal = headerPrefix + val
		}
		return map[string]string{
			headerName: headerVal,
		}, nil
	}
}

// DefaultTokenExtractor extracts the Warden session token from X-Warden-Token
// or Authorization: Bearer headers. This is the default for most providers.
func DefaultTokenExtractor(r *http.Request) string {
	if token := r.Header.Get("X-Warden-Token"); token != "" {
		return token
	}
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
		return authHeader[7:]
	}
	return ""
}
