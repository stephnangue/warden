package cert

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

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
				Description:   "Identity source from certificate: cn (default), dns_san, email_san, uri_san, serial",
				Default:       "cn",
				AllowedValues: principalClaimAllowedValues(),
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default token TTL (default: 1h)",
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

Set 'trusted_ca_pem' to the CA bundle that signs client certificates and
'principal_claim' to the identity field (cn, dns_san, email_san, uri_san, or
serial).`,
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
			"trusted_ca_count": certCount,
			"token_ttl":        b.config.TokenTTL.String(),
			"revocation_mode":  b.config.RevocationMode,
			"crl_cache_ttl":    b.config.CRLCacheTTL,
			"ocsp_timeout":     b.config.OCSPTimeout,
			"default_role":     b.config.DefaultRole,
		},
	}, nil
}

// handleConfigWrite handles writing the configuration.
//
// The write is built, persisted, and only then installed, so a write that is
// refused or cannot be stored leaves the mount authenticating against what
// storage holds. Writes are serialized, so each merges onto the configuration
// the previous one left.
func (b *certAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	// Build config map from field data
	conf := make(map[string]any)

	// Copy existing config if present
	b.configMu.RLock()
	if b.config != nil {
		conf["trusted_ca_pem"] = b.config.TrustedCAPEM
		conf["principal_claim"] = b.config.PrincipalClaim
		conf["token_ttl"] = b.config.TokenTTL
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

	// Build new config
	config, err := buildCertConfig(ctx, conf)
	if err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        err,
		}, nil
	}

	// Persist the normalized config before installing it
	if b.storageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", normalizedCertConfig(config))
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
