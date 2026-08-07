package drivers

import (
	"strings"

	"github.com/stephnangue/warden/credential"
)

// DeriveAssertionResource returns the canonical downstream resource a
// warden_identity federation spec targets, or ("", false) when there is no single
// statically-known one. It is pure: it reads the source and spec config maps only
// and never builds a live driver or touches the network — so it is safe to call
// eagerly on every request, before the credential cache, without risking a
// per-request STS/Entra probe for a misconfigured spec.
//
// It dispatches on the source type to the same driver that would consume the
// assertion, keeping each provider's config-key knowledge next to that driver's
// other reads. A source type with no federation resource (or an unknown one)
// returns ("", false), so the warden_resource claim is simply omitted.
//
// The returned value is opaque: it carries a human-readable provider prefix but
// must never be parsed back into parts, since a resource identifier (e.g. a Vault
// KV path) can itself contain the ':' delimiter.
func DeriveAssertionResource(sourceType string, sourceCfg, specCfg map[string]string) (string, bool) {
	switch sourceType {
	case credential.SourceTypeAWS:
		return awsAssertionResource(specCfg)
	case credential.SourceTypeAzure:
		return azureAssertionResource(specCfg)
	case credential.SourceTypeTokenExchange:
		return tokenExchangeAssertionResource(sourceCfg, specCfg)
	case credential.SourceTypeGCP:
		return gcpAssertionResource(sourceCfg, specCfg)
	default:
		return "", false
	}
}

// DeriveAssertionAudience returns the `aud` a warden_identity assertion should be
// minted with when the spec does not set assertion_audience explicitly, or
// ("", false) when the source type cannot supply one. Like DeriveAssertionResource
// it is pure — reads the source and spec config maps only, no network or live
// driver — so it is safe to call on every request before the credential cache.
//
// The audience is a property of the source's federation trust relationship, not of
// an individual spec, so deriving it here lets an operator configure it once on the
// source (or rely on the driver's conventional default) instead of repeating it on
// every spec. An explicit spec assertion_audience always takes precedence; this is
// consulted only as the fallback.
func DeriveAssertionAudience(sourceType string, sourceCfg, specCfg map[string]string) (string, bool) {
	switch sourceType {
	case credential.SourceTypeGCP:
		return gcpAssertionAudience(sourceCfg)
	default:
		return "", false
	}
}

// gcpAssertionAudience derives the GCP WIF assertion audience from the source's
// workload_identity_provider. GCP STS takes the scheme-relative provider name
// (//iam.googleapis.com/...) as the exchange audience parameter, while the JWT `aud`
// claim must match the provider's allowed audiences, which default to the
// https://iam.googleapis.com/-prefixed form. Swap only the leading "//" so an
// incidental "//" later in the path cannot be corrupted.
//
// Gated on auth_method=oidc_federation, like awsAssertionAudience/azureAssertionAudience,
// so only a keyless source derives an audience even if a stored config record somehow
// carries a provider on a non-federation source (ValidateConfig already forbids that
// combination; this is the matching derive-time guard).
func gcpAssertionAudience(sourceCfg map[string]string) (string, bool) {
	if credential.GetString(sourceCfg, "auth_method", gcpAuthMethodStatic) != gcpAuthMethodOIDCFederation {
		return "", false
	}
	provider := credential.GetString(sourceCfg, "workload_identity_provider", "")
	if provider == "" || !strings.HasPrefix(provider, "//") {
		return "", false
	}
	return "https://" + strings.TrimPrefix(provider, "//"), true
}
