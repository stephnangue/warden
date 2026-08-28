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
	case credential.SourceTypeVault:
		return vaultAssertionResource(sourceCfg, specCfg)
	case credential.SourceTypeKubernetes:
		return kubernetesAssertionResource(specCfg)
	case credential.SourceTypeAlicloud:
		return alicloudAssertionResource(specCfg)
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
	case credential.SourceTypeAWS:
		return awsAssertionAudience(sourceCfg)
	case credential.SourceTypeAzure:
		return azureAssertionAudience(sourceCfg)
	case credential.SourceTypeVault:
		return vaultAssertionAudience(sourceCfg)
	case credential.SourceTypeKubernetes:
		return kubernetesAssertionAudience(sourceCfg)
	case credential.SourceTypeAlicloud:
		return alicloudAssertionAudience(sourceCfg)
	default:
		return "", false
	}
}

// alicloudAssertionAudience derives the warden_identity assertion audience for a
// keyless Alicloud source: the source's explicit `audience`, or ("", false) when
// unset. There is no conventional default — unlike AWS, which accepts
// sts.amazonaws.com, Alibaba matches the assertion's aud against the client_ids
// registered on the RAM OIDC provider, which the operator chooses — so an unset
// audience forces the spec to set assertion_audience (the spec-create gate
// enforces this, and mint fails closed otherwise).
//
// Gated on auth_method=oidc_federation: only a keyless source federates, so a
// static source supplies no derived audience even if a stored config record
// somehow carries one.
func alicloudAssertionAudience(sourceCfg map[string]string) (string, bool) {
	if credential.GetString(sourceCfg, "auth_method", alicloudAuthMethodStatic) != alicloudAuthMethodOIDCFederation {
		return "", false
	}
	if aud := credential.GetString(sourceCfg, "audience", ""); aud != "" {
		return aud, true
	}
	return "", false
}

// alicloudAssertionResource reports the RAM role a federation spec assumes, for
// the warden_resource claim. Pure: reads spec config only, no network or driver
// state. The driver has a single mint path, so unlike the multi-engine sources
// there is no mint_method to dispatch on.
//
// The provider prefix is human-readable sugar on an opaque value — never parse it
// back, since a role ARN contains ':' itself.
func alicloudAssertionResource(specCfg map[string]string) (string, bool) {
	if arn := credential.GetString(specCfg, "role_arn", ""); arn != "" {
		return "alicloud-ram:" + arn, true
	}
	return "", false
}

// kubernetesAssertionAudience derives the warden_identity assertion audience for a
// keyless Kubernetes source: the source's explicit `audience`, or ("", false) when
// unset. There is no conventional default — the value must appear in the cluster
// authenticator's own audiences list, which the operator chooses — so an unset
// audience forces the spec to set assertion_audience (the spec-create gate enforces
// this, and mint fails closed otherwise).
//
// Gated on auth_method=oidc_federation: only a keyless source federates, so a
// static source supplies no derived audience even if a stored config record somehow
// carries one.
func kubernetesAssertionAudience(sourceCfg map[string]string) (string, bool) {
	if credential.GetString(sourceCfg, "auth_method", kubernetesAuthMethodStatic) != kubernetesAuthMethodOIDCFederation {
		return "", false
	}
	if aud := credential.GetString(sourceCfg, "audience", ""); aud != "" {
		return aud, true
	}
	return "", false
}

// kubernetesAssertionResource reports the service account a federation spec mints
// for, as "namespace/service_account", for the warden_resource claim. Pure: reads
// spec config only, no network or driver state. The driver has a single mint path,
// so unlike the multi-engine sources there is no mint_method to dispatch on.
//
// The returned value is opaque — never parse it back, since a Kubernetes name can
// in principle carry the separator.
func kubernetesAssertionResource(specCfg map[string]string) (string, bool) {
	namespace := credential.GetString(specCfg, "namespace", "")
	sa := credential.GetString(specCfg, "service_account", "")
	if namespace != "" && sa != "" {
		return namespace + "/" + sa, true
	}
	return "", false
}

// vaultAssertionAudience derives the warden_identity assertion audience for a Vault
// (hvault) federation source: the source's explicit `audience`, or ("", false) when
// unset. Unlike AWS/Azure there is no conventional Vault default — the audience must
// equal the Vault JWT-auth role's bound_audiences, which the operator chooses — so an
// unset audience forces the spec to set assertion_audience explicitly (the spec-create
// gate enforces this, and mint fails closed otherwise).
//
// Gated on auth_method=oidc_federation: only a keyless source federates, so a static
// (approle/token) source supplies no derived audience even if a stored config record
// somehow carries one.
func vaultAssertionAudience(sourceCfg map[string]string) (string, bool) {
	if credential.GetString(sourceCfg, "auth_method", "") != vaultAuthMethodOIDCFederation {
		return "", false
	}
	if aud := credential.GetString(sourceCfg, "audience", ""); aud != "" {
		return aud, true
	}
	return "", false
}

// vaultAssertionResource reports the canonical downstream resource a Vault federation
// spec targets, for the warden_resource assertion claim. Pure: reads source/spec
// config only, no network or driver state. Dispatches on the spec's mint_method, since
// that selects which upstream engine/path the federated session actually reaches. The
// returned value is the bare mount/path (or role) with no provider prefix; it is
// opaque — never parse it back, as a KV path or role name can itself contain ':'.
func vaultAssertionResource(sourceCfg, specCfg map[string]string) (string, bool) {
	switch credential.GetString(specCfg, "mint_method", "") {
	case "vault_token":
		// The effective JWT-auth role: a spec override falls back to the source value.
		role := credential.GetString(specCfg, "jwt_role", "")
		if role == "" {
			role = credential.GetString(sourceCfg, "jwt_role", "")
		}
		if role != "" {
			return role, true
		}
	case "static_aws", "static_apikey", "kv2_read":
		mount := credential.GetString(specCfg, "kv2_mount", "")
		path := credential.GetString(specCfg, "secret_path", "")
		if mount != "" && path != "" {
			return mount + "/" + path, true
		}
	case "dynamic_aws":
		if mount, role := credential.GetString(specCfg, "aws_mount", ""), credential.GetString(specCfg, "role_name", ""); mount != "" && role != "" {
			return mount + "/" + role, true
		}
	case "dynamic_gcp":
		if mount, role := credential.GetString(specCfg, "gcp_mount", ""), credential.GetString(specCfg, "role_name", ""); mount != "" && role != "" {
			return mount + "/" + role, true
		}
	case "dynamic_ibm":
		if mount, role := credential.GetString(specCfg, "ibm_mount", ""), credential.GetString(specCfg, "role_name", ""); mount != "" && role != "" {
			return mount + "/" + role, true
		}
	case "oauth2":
		mount := credential.GetString(specCfg, "oauth2_mount", "")
		name := credential.GetString(specCfg, "credential_name", "")
		if mount != "" && name != "" {
			return mount + "/" + name, true
		}
	}
	return "", false
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
