// Package dualgateway provides a framework for building dual-mode gateway
// providers that auto-detect between REST API proxying and S3-compatible
// Object Storage (SigV4 verify/re-sign/forward) per request.
//
// Providers supply a ProviderSpec describing their differences (auth strategy,
// S3 endpoint format, credential type); the framework handles everything else:
// transport, token extraction, transparent auth, config CRUD, SigV4 lifecycle.
package dualgateway

import (
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// APIAuthStrategy defines how the provider injects credentials into REST API requests.
type APIAuthStrategy struct {
	// HeaderName is the header to set (e.g., "X-Auth-Token", "Authorization").
	HeaderName string

	// HeaderValueFormat is a fmt-style format string applied to the credential value.
	// Use "%s" for raw injection (e.g., X-Auth-Token: {secret_key}).
	// Use "Bearer %s" for Bearer injection (e.g., Authorization: Bearer {token}).
	HeaderValueFormat string

	// CredentialField is the field name to extract from the credential's Data map
	// (e.g., "secret_key", "api_token"). Used by the default ExtractAPICredential.
	CredentialField string

	// StripAuthorization controls whether the incoming Authorization header
	// is removed before injecting the provider's auth header.
	// true  = strip it (OVH: replaces Authorization with its own Bearer token)
	// false = keep it (Scaleway: uses X-Auth-Token, leaves Authorization alone)
	StripAuthorization bool
}

// ProviderSpec fully describes a dual-mode gateway provider.
// All shared behavior (transport, token extraction, SigV4 verify/re-sign,
// config CRUD, transparent auth) is handled by the dualgateway package;
// only provider-specific differences are captured here.
type ProviderSpec struct {
	// --- Identity ---

	// Name is the provider identifier (e.g., "scaleway", "ovh").
	Name string

	// HelpText is the backend help description.
	HelpText string

	// CredentialType is the expected credential type constant
	// (e.g., credential.TypeScalewayKeys, credential.TypeOVHKeys).
	CredentialType string

	// --- API Mode Configuration ---

	// DefaultURL is the upstream REST API base URL
	// (e.g., "https://api.scaleway.com", "https://eu.api.ovh.com/1.0").
	DefaultURL string

	// URLConfigKey is the config key for the URL
	// (e.g., "scaleway_url", "ovh_url").
	URLConfigKey string

	// DefaultTimeout is the default request timeout.
	DefaultTimeout time.Duration

	// UserAgent is the User-Agent header injected into proxied requests
	// (e.g., "warden-scaleway-proxy", "warden-ovh-proxy").
	UserAgent string

	// APIAuth defines how REST API credentials are injected.
	APIAuth APIAuthStrategy

	// --- S3 Mode Configuration ---

	// S3Endpoint builds the S3 target hostname from provider state and the SigV4 region.
	// The state map contains values extracted by OnConfigParsed (e.g., account_id).
	// For providers that don't need state, ignore the first argument.
	// Examples:
	//   Scaleway: func(_ map[string]any, region string) string { return fmt.Sprintf("s3.%s.scw.cloud", region) }
	//   OVH:      func(_ map[string]any, region string) string { return fmt.Sprintf("s3.%s.io.cloud.ovh.net", region) }
	//   R2:       func(state map[string]any, region string) string { return fmt.Sprintf("%s.r2.cloudflarestorage.com", state["account_id"]) }
	S3Endpoint func(state map[string]any, region string) string

	// --- Optional Extensibility Hooks ---

	// ExtraConfigKeys are additional allowed config keys beyond the standard set
	// (url, max_body_size, timeout, auto_auth_path, default_role, tls_skip_verify, ca_data).
	ExtraConfigKeys []string

	// ExtraConfigFields defines field schemas for extra config keys.
	// If nil, extra keys are treated as TypeString.
	ExtraConfigFields map[string]*framework.FieldSchema

	// OnConfigParsed is called after standard config parsing to extract
	// provider-specific fields. Returns a state map stored on the backend.
	// If nil, no extra state is maintained.
	OnConfigParsed func(config map[string]any) map[string]any

	// --- Optional Credential Extraction Overrides ---

	// ExtractAPICredential extracts the API auth credential value from the
	// request's Warden credential. If nil, the framework uses a default
	// that reads APIAuth.CredentialField from credential.Data after
	// validating CredentialType.
	ExtractAPICredential func(req *logical.Request) (string, error)

	// ExtractS3Credentials extracts real provider S3 credentials from the
	// request's Warden credential. If nil, the framework uses a default
	// that reads "access_key" and "secret_key" from credential.Data
	// after validating CredentialType.
	ExtractS3Credentials func(req *logical.Request) (awssdk.Credentials, error)

	// --- Optional API-mode URL override ---

	// RewriteAPITarget, if non-nil, overrides API-mode target URL construction.
	// Default behavior (nil): targetURL = providerURL + apiPath.
	//
	// Providers that route to multiple upstream hostnames based on the request
	// path (e.g., IBM Cloud, where each service has a different host) use this
	// hook to parse the path and build the correct target URL.
	//
	// Arguments:
	//   providerURL - the configured upstream URL (may be ignored)
	//   apiPath     - the path after "/gateway" (always starts with "/", possibly just "/")
	//   state       - the map produced by OnConfigParsed (may be nil)
	//
	// Returns:
	//   full target URL (scheme + host + path + optional query) on success
	//   non-nil error to reject the request with HTTP 400
	//
	// Only invoked for API-mode requests; SigV4 (S3/COS) requests continue to use
	// S3Endpoint and are never routed through this hook.
	RewriteAPITarget func(providerURL, apiPath string, state map[string]any) (string, error)
}
