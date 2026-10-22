package jwt

import (
	"context"
	"maps"
	"net/http"
	"slices"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition
func (b *jwtAuthBackend) pathConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{
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
			Description: "Audiences a JWT must carry, any one of them. Required when entity_kind is agent.",
		},
		"bound_subject": {
			Type:        framework.TypeString,
			Description: "Required subject for JWT validation",
		},
		"bound_claims": {
			Type:        framework.TypeMap,
			Description: "Map of claims to required values for JWT validation",
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
		"max_age": helper.MaxAgeFieldSchema(),
		"default_role": {
			Type:        framework.TypeString,
			Description: "Default role for transparent operations when no role is specified",
		},
	}
	maps.Copy(fields, helper.FactsFieldSchemas("a claim name, or a JSON Pointer with a leading / into nested claims"))

	return &framework.Path{
		Pattern: "config",
		Fields:  fields,
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
to constrain which tokens are admitted. 'bound_audiences' is required on a
mount that admits agents: without it, a token the issuer minted for any other
relying party would be admitted.

'entity_kind' (agent or human, default agent) names what the mount admits.
'facts' maps source claims to the fact names the mount publishes beyond its
built-in facts (sub, iss, aud); a write replaces the whole map.
'max_age' bounds a JWT's age at admission, from its iat: a JWT older than it,
or without an iat, is not admitted.`,
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
			"jwt_validation_pubkeys": slices.Clone(b.config.JWTValidationPubKeys),
			"bound_issuer":           b.config.BoundIssuer,
			"bound_audiences":        slices.Clone(b.config.BoundAudiences),
			"bound_subject":          b.config.BoundSubject,
			"bound_claims":           b.config.BoundClaims,
			"user_claim":             b.config.UserClaim,
			"groups_claim":           b.config.GroupsClaim,
			"group_policy_prefix":    b.config.GroupPolicyPrefix,
			"token_ttl":              b.config.TokenTTL.String(),
			"max_age":                b.config.MaxAge.String(),
			"default_role":           b.config.DefaultRole,
			"entity_kind":            b.config.EntityKind,
			"facts":                  maps.Clone(b.config.Facts),
		},
	}, nil
}

// handleConfigWrite handles writing the configuration.
//
// The write is built, persisted, and only then installed, so a write that is
// refused or cannot be stored leaves the mount authenticating against what
// storage holds. Writes are serialized, so each merges onto the configuration
// the previous one left.
func (b *jwtAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	// Build config map from field data
	conf := make(map[string]any)

	_, factsSent := d.GetOk("facts")
	_, kindSent := d.GetOk("entity_kind")
	factsTouched := factsSent || kindSent

	// Copy existing config if present (under lock to avoid data race)
	b.configMu.RLock()
	if b.config != nil {
		// Stored facts that do not compile would fail a write that leaves
		// them in place, whatever else it changes; say how to replace them
		// before any key set is fetched.
		if !factsTouched {
			if err := helper.FactsWriteError(&b.config.FactsConfig, false); err != nil {
				b.configMu.RUnlock()
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}, nil
			}
		}
		conf["oidc_discovery_url"] = b.config.OIDCDiscoveryURL
		conf["oidc_discovery_ca_pem"] = b.config.OIDCDiscoveryCA
		conf["jwks_url"] = b.config.JWKSURL
		conf["jwks_ca_pem"] = b.config.JWKSCA
		conf["jwt_validation_pubkeys"] = b.config.JWTValidationPubKeys
		conf["bound_issuer"] = b.config.BoundIssuer
		conf["bound_audiences"] = b.config.BoundAudiences
		conf["bound_subject"] = b.config.BoundSubject
		conf["bound_claims"] = b.config.BoundClaims
		conf["user_claim"] = b.config.UserClaim
		conf["groups_claim"] = b.config.GroupsClaim
		conf["group_policy_prefix"] = b.config.GroupPolicyPrefix
		conf["token_ttl"] = b.config.TokenTTL
		conf["max_age"] = b.config.MaxAge
		conf["default_role"] = b.config.DefaultRole
		conf["entity_kind"] = b.config.EntityKind
		conf["facts"] = b.config.Facts
	}
	b.configMu.RUnlock()

	// Apply new values from request
	for key := range d.Schema {
		if val, ok := d.GetOk(key); ok {
			conf[key] = val
		}
	}

	// A facts write replaces the whole mapping; every name must be a string.
	if raw, ok := d.GetOk("facts"); ok {
		facts, err := helper.ParseFactsField(raw)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        err,
			}, nil
		}
		conf["facts"] = facts
	}

	// Build new config
	config, err := buildJWTConfig(ctx, conf)
	if err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}
	// A write is the one place facts can be refused outright; storage and
	// load only ever see a config that compiled here.
	if err := helper.FactsWriteError(&config.FactsConfig, factsTouched); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}
	// An agent mount binds an audience; a stored config without one refuses
	// admission, and a write cannot create one.
	if helper.RequireAgentAudiences(config.EntityKind, config.BoundAudiences) != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        helper.AgentAudiencesWriteError(),
		}, nil
	}

	// Persist the normalized config before installing it
	if b.storageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", normalizedJWTConfig(config))
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

	b.installConfig(config)

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
