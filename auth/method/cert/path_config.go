package cert

import (
	"context"
	"maps"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition
func (b *certAuthBackend) pathConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{
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
	}
	maps.Copy(fields, helper.FactsFieldSchemas(factsSources))

	return &framework.Path{
		Pattern: "config",
		Fields:  fields,
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
serial).

'entity_kind' (agent or human, default agent) names what the mount admits.
'facts' maps certificate fields to the fact names the mount publishes beyond
its built-in facts (ca, cn, dns_san, email_san, org, ou, serial, uri_san; ca
is the SHA-256 fingerprint of each trust anchor the certificate verified to); a
write replaces the whole map.`,
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
			"entity_kind":      b.config.EntityKind,
			"facts":            maps.Clone(b.config.Facts),
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

	_, factsSent := d.GetOk("facts")
	_, kindSent := d.GetOk("entity_kind")
	factsTouched := factsSent || kindSent

	// Copy existing config if present
	b.configMu.RLock()
	if b.config != nil {
		// Stored facts that do not compile would fail a write that leaves
		// them in place, whatever else it changes; say how to replace them.
		if !factsTouched {
			if err := helper.FactsWriteError(&b.config.FactsConfig, false); err != nil {
				b.configMu.RUnlock()
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        err,
				}, nil
			}
		}
		conf["trusted_ca_pem"] = b.config.TrustedCAPEM
		conf["principal_claim"] = b.config.PrincipalClaim
		conf["token_ttl"] = b.config.TokenTTL
		conf["revocation_mode"] = b.config.RevocationMode
		conf["crl_cache_ttl"] = b.config.CRLCacheTTL
		conf["ocsp_timeout"] = b.config.OCSPTimeout
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
	config, err := buildCertConfig(ctx, conf)
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
