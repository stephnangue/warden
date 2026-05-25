package jwt

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition
func (b *jwtAuthBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"oidc_discovery_url": {
				Type:        framework.TypeString,
				Description: "OIDC Discovery URL. Set exactly one of oidc_discovery_url, jwks_url, or jwt_validation_pubkeys.",
			},
			"oidc_discovery_ca_pem": {
				Type:        framework.TypeString,
				Description: "CA certificate for OIDC discovery",
			},
			"jwks_url": {
				Type:        framework.TypeString,
				Description: "JWKS URL. Set exactly one of oidc_discovery_url, jwks_url, or jwt_validation_pubkeys.",
			},
			"jwks_ca_pem": {
				Type:        framework.TypeString,
				Description: "CA certificate for JWKS endpoint",
			},
			"bound_issuer": {
				Type:        framework.TypeString,
				Description: "Required issuer for JWT validation",
			},
			"bound_audiences": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Required audiences for JWT validation",
			},
			"bound_subject": {
				Type:        framework.TypeString,
				Description: "Required subject for JWT validation",
			},
			"bound_claims": {
				Type:        framework.TypeMap,
				Description: "Map of claims to required values for JWT validation",
			},
			"claim_mappings": {
				Type:        framework.TypeKVPairs,
				Description: "Map of claims to copy to token metadata",
			},
			"jwt_validation_pubkeys": {
				Type:        framework.TypeCommaStringSlice,
				Description: "PEM-encoded RSA or ECDSA public keys for static JWT validation. Set exactly one of oidc_discovery_url, jwks_url, or jwt_validation_pubkeys.",
			},
			"user_claim": {
				Type:        framework.TypeString,
				Description: "Claim to use as principal identity (default: sub)",
				Default:     "sub",
			},
			"groups_claim": {
				Type:        framework.TypeString,
				Description: "JWT claim containing group names for dynamic policy mapping. Empty disables group-based policies.",
			},
			"group_policy_prefix": {
				Type:        framework.TypeString,
				Description: "Prefix prepended to each group name to form the policy name (default: group-)",
				Default:     "group-",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token TTL (default: 1h)",
			},
			"default_role": {
				Type:        framework.TypeString,
				Description: "Default role for transparent operations when no role is specified",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read JWT auth configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure JWT authentication",
			},
		},
		HelpSynopsis: "Configure JWT authentication",
		HelpDescription: `This endpoint configures the JWT authentication method.

Set exactly one of 'oidc_discovery_url' (OIDC discovery), 'jwks_url' (JWKS
endpoint), or 'jwt_validation_pubkeys' (static PEM-encoded RSA/ECDSA keys)
to configure how token signatures are verified.

Use 'bound_issuer', 'bound_audiences', 'bound_subject', and 'bound_claims'
to constrain which tokens are accepted. Use 'claim_mappings' to copy JWT
claims into token metadata for use in policies.`,
	}
}

// handleConfigRead handles reading the configuration
func (b *jwtAuthBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	if b.config == nil {
		return &logical.Response{
			StatusCode: http.StatusOK,
			Data:       map[string]any{},
		}, nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"oidc_discovery_url":     b.config.OIDCDiscoveryURL,
			"oidc_discovery_ca_pem":  b.config.OIDCDiscoveryCA,
			"jwks_url":               b.config.JWKSURL,
			"jwks_ca_pem":            b.config.JWKSCA,
			"jwt_validation_pubkeys": b.config.JWTValidationPubKeys,
			"bound_issuer":           b.config.BoundIssuer,
			"bound_audiences":        b.config.BoundAudiences,
			"bound_subject":          b.config.BoundSubject,
			"bound_claims":           b.config.BoundClaims,
			"claim_mappings":         b.config.ClaimMappings,
			"user_claim":             b.config.UserClaim,
			"groups_claim":           b.config.GroupsClaim,
			"group_policy_prefix":    b.config.GroupPolicyPrefix,
			"token_ttl":              b.config.TokenTTL.String(),
			"default_role":           b.config.DefaultRole,
		},
	}, nil
}

// handleConfigWrite handles writing the configuration
func (b *jwtAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Build config map from field data
	conf := make(map[string]any)

	// Copy existing config if present (under lock to avoid data race)
	b.configMu.RLock()
	if b.config != nil {
		conf["oidc_discovery_url"] = b.config.OIDCDiscoveryURL
		conf["oidc_discovery_ca_pem"] = b.config.OIDCDiscoveryCA
		conf["jwks_url"] = b.config.JWKSURL
		conf["jwks_ca_pem"] = b.config.JWKSCA
		conf["jwt_validation_pubkeys"] = b.config.JWTValidationPubKeys
		conf["bound_issuer"] = b.config.BoundIssuer
		conf["bound_audiences"] = b.config.BoundAudiences
		conf["bound_subject"] = b.config.BoundSubject
		conf["bound_claims"] = b.config.BoundClaims
		conf["claim_mappings"] = b.config.ClaimMappings
		conf["user_claim"] = b.config.UserClaim
		conf["groups_claim"] = b.config.GroupsClaim
		conf["group_policy_prefix"] = b.config.GroupPolicyPrefix
		conf["token_ttl"] = b.config.TokenTTL
		conf["default_role"] = b.config.DefaultRole
	}
	b.configMu.RUnlock()

	// Apply new values from request
	for key := range d.Schema {
		if val, ok := d.GetOk(key); ok {
			conf[key] = val
		}
	}

	// Setup new config
	if err := b.setupJWTConfig(ctx, conf); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	// Persist the normalized config to storage so that on restart the
	// parser always sees consistent types (e.g., token_ttl is always a
	// duration string, never a raw int from an HTTP request).
	if b.storageView != nil {
		b.configMu.RLock()
		normalized := map[string]any{
			"oidc_discovery_url":     b.config.OIDCDiscoveryURL,
			"oidc_discovery_ca_pem":  b.config.OIDCDiscoveryCA,
			"jwks_url":               b.config.JWKSURL,
			"jwks_ca_pem":            b.config.JWKSCA,
			"jwt_validation_pubkeys": b.config.JWTValidationPubKeys,
			"bound_issuer":           b.config.BoundIssuer,
			"bound_audiences":        b.config.BoundAudiences,
			"bound_subject":          b.config.BoundSubject,
			"bound_claims":           b.config.BoundClaims,
			"claim_mappings":         b.config.ClaimMappings,
			"user_claim":             b.config.UserClaim,
			"groups_claim":           b.config.GroupsClaim,
			"group_policy_prefix":    b.config.GroupPolicyPrefix,
			"token_ttl":              b.config.TokenTTL.String(),
			"default_role":           b.config.DefaultRole,
		}
		b.configMu.RUnlock()

		entry, err := sdklogical.StorageEntryJSON("config", normalized)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}, nil
		}
		if err := b.storageView.Put(ctx, entry); err != nil {
			return &logical.Response{
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}, nil
		}
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"message": "configuration updated",
		},
	}, nil
}

const jwtAuthHelp = `
The JWT auth method authenticates users by validating JSON Web Tokens
signed by a trusted identity provider.

Three key sources are supported; exactly one must be configured per mount:

  oidc_discovery_url     - OIDC Discovery (/.well-known/openid-configuration).
                           Suitable for SSO with providers like Okta, Auth0,
                           or Azure AD.
  jwks_url               - JWKS endpoint. Suitable for service-to-service
                           auth and CI/CD pipelines with a reachable JWKS
                           server.
  jwt_validation_pubkeys - Static PEM-encoded RSA or ECDSA public keys.
                           Suitable for air-gapped clusters and fixed-issuer
                           workloads where no JWKS endpoint is reachable.

Tokens are validated against configurable bound claims (issuer, audience,
subject, custom claims). The user_claim field (default: sub) determines the
authenticated principal identity.

Configuration:
  POST /auth/{mount}/config   - Configure key source and claim bindings
  GET  /auth/{mount}/config   - Read current configuration
  POST /auth/{mount}/role/:name - Create roles with per-role claim constraints
`
