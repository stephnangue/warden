package drivers

import "github.com/stephnangue/warden/credential"

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
