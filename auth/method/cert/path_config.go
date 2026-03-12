package cert

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition
func (b *certAuthBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"trusted_ca_pem": {
				Type:        framework.TypeString,
				Description: "PEM-encoded trusted CA certificates",
			},
			"principal_claim": {
				Type:          framework.TypeString,
				Description:   "Identity source from certificate: cn (default), spiffe_id, dns_san, email_san, uri_san, serial",
				Default:       "cn",
				AllowedValues: principalClaimAllowedValues(),
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default token TTL (default: 1h)",
			},
			"token_type": {
				Type:          framework.TypeString,
				Description:   "Default token type for roles that don't specify one (default: transparent)",
				Default:       "transparent",
				AllowedValues: b.allowedTokenTypeValues(),
			},
			"revocation_mode": {
				Type:        framework.TypeString,
				Description: "Certificate revocation checking mode: none (default), crl, ocsp, best_effort",
				Default:     "none",
			},
			"crl_cache_ttl": {
				Type:        framework.TypeString,
				Description: "CRL cache TTL (default: 1h). Example: 30m, 2h",
				Default:     "1h",
			},
			"ocsp_timeout": {
				Type:        framework.TypeString,
				Description: "OCSP request timeout (default: 5s). Example: 3s, 10s",
				Default:     "5s",
			},
			"default_role": {
				Type:        framework.TypeString,
				Description: "Default role for transparent operations when no role is specified",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read certificate auth configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure certificate authentication",
			},
		},
		HelpSynopsis: "Configure certificate authentication",
		HelpDescription: `This endpoint configures the certificate authentication method.

Set 'trusted_ca_pem' to PEM-encoded CA certificates that sign client certificates.
Use 'principal_claim' to control which certificate field identifies the principal
(cn, dns_san, email_san, uri_san, or serial).`,
	}
}

// handleConfigRead handles reading the configuration
func (b *certAuthBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	if b.config == nil {
		return &logical.Response{
			StatusCode: http.StatusOK,
			Data:       map[string]any{},
		}, nil
	}

	certCount := 0
	if b.config.TrustedCAPEM != "" {
		certCount = parsePEMCertificates(b.config.TrustedCAPEM)
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"trusted_ca_pem":   b.config.TrustedCAPEM,
			"principal_claim":  b.config.PrincipalClaim,
			"token_ttl":        b.config.TokenTTL.String(),
			"token_type":       helper.DisplayTokenType(b.config.TokenType),
			"revocation_mode":  b.config.RevocationMode,
			"crl_cache_ttl":    b.config.CRLCacheTTL,
			"ocsp_timeout":     b.config.OCSPTimeout,
			"default_role":     b.config.DefaultRole,
			"trusted_ca_count": certCount,
		},
	}, nil
}

// handleConfigWrite handles writing the configuration
func (b *certAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Build config map from field data
	conf := make(map[string]any)

	// Copy existing config if present
	b.configMu.RLock()
	if b.config != nil {
		conf["trusted_ca_pem"] = b.config.TrustedCAPEM
		conf["principal_claim"] = b.config.PrincipalClaim
		conf["token_ttl"] = b.config.TokenTTL
		conf["token_type"] = b.config.TokenType
		conf["revocation_mode"] = b.config.RevocationMode
		conf["crl_cache_ttl"] = b.config.CRLCacheTTL
		conf["ocsp_timeout"] = b.config.OCSPTimeout
		conf["default_role"] = b.config.DefaultRole
	}
	b.configMu.RUnlock()

	// Apply new values from request
	for key := range d.Schema {
		if val, ok := d.GetOk(key); ok {
			conf[key] = val
		}
	}

	// Translate user-facing token_type alias to internal name before setup
	if rawType, ok := conf["token_type"].(string); ok {
		conf["token_type"] = helper.ResolveTokenType(helper.BackendCert, rawType)
	}

	// Setup new config
	if err := b.setupCertConfig(ctx, conf); err != nil {
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
			"trusted_ca_pem":  b.config.TrustedCAPEM,
			"principal_claim": b.config.PrincipalClaim,
			"token_ttl":       b.config.TokenTTL.String(),
			"token_type":      b.config.TokenType,
			"revocation_mode": b.config.RevocationMode,
			"crl_cache_ttl":   b.config.CRLCacheTTL,
			"ocsp_timeout":    b.config.OCSPTimeout,
			"default_role": b.config.DefaultRole,
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
