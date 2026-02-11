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
			"mode": {
				Type:        framework.TypeString,
				Description: "Authentication mode: 'jwt' or 'oidc' (required)",
				Required:    true,
			},
			"oidc_discovery_url": {
				Type:        framework.TypeString,
				Description: "OIDC Discovery URL (required for OIDC mode, mutually exclusive with jwks_url)",
			},
			"oidc_discovery_ca_pem": {
				Type:        framework.TypeString,
				Description: "CA certificate for OIDC discovery",
			},
			"jwks_url": {
				Type:        framework.TypeString,
				Description: "JWKS URL (required for JWT mode, mutually exclusive with oidc_discovery_url)",
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
				Type:        framework.TypeKVPairs,
				Description: "Map of claims to required values for JWT validation",
			},
			"claim_mappings": {
				Type:        framework.TypeKVPairs,
				Description: "Map of claims to copy to token metadata",
			},
			"jwt_validation_pubkeys": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of PEM-encoded public keys for JWT validation (alternative to jwks_url)",
			},
			"user_claim": {
				Type:        framework.TypeString,
				Description: "Claim to use as principal identity (default: sub)",
				Default:     "sub",
			},
			"groups_claim": {
				Type:        framework.TypeString,
				Description: "Claim to use for groups (default: groups)",
				Default:     "groups",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token TTL (default: 1h)",
			},
			"token_type": {
				Type:          framework.TypeString,
				Description:   "Default token type for roles that don't specify one (default: warden_token)",
				Default:       "warden_token",
				AllowedValues: b.allowedTokenTypeValues(),
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
		HelpSynopsis:    "Configure JWT authentication",
		HelpDescription: "This endpoint configures JWT/OIDC authentication settings.",
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
			"mode":                   b.config.Mode,
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
			"user_claim":   b.config.UserClaim,
			"groups_claim": b.config.GroupsClaim,
			"token_ttl":    b.config.TokenTTL.String(),
			"token_type":   b.config.TokenType,
		},
	}, nil
}

// handleConfigWrite handles writing the configuration
func (b *jwtAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Build config map from field data
	conf := make(map[string]any)

	// Copy existing config if present
	if b.config != nil {
		conf["mode"] = b.config.Mode
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
		conf["token_ttl"] = b.config.TokenTTL
		conf["token_type"] = b.config.TokenType
	}

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

	// Persist config to storage
	if b.storageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", conf)
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
The JWT auth backend authenticates users using JSON Web Tokens.

It supports both JWT mode (with JWKS URL) and OIDC mode (with OIDC Discovery).
`
