package cert

import (
	"context"
	"fmt"
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
			"mode": {
				Type:          framework.TypeString,
				Description:   "Trust model for this mount: x509 (default, classic PKI) or spiffe (SPIFFE X.509-SVID).",
				Default:       modeX509,
				AllowedValues: []interface{}{modeX509, modeSPIFFE},
			},
			"trusted_ca_pem": {
				Type:        framework.TypeString,
				Description: "PEM-encoded trusted CA certificates (x509 mode only)",
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

Set 'mode' to choose the trust model: x509 (default, classic PKI) or spiffe
(SPIFFE X.509-SVID). In x509 mode, set 'trusted_ca_pem' to the CA bundle that
signs client certificates and 'principal_claim' to the identity field
(cn, dns_san, email_san, uri_san, or serial). In spiffe mode, register trust
domains under spiffe/trust-domain/ instead; those PKI fields are not used.`,
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

	mode := b.config.Mode
	if mode == "" {
		mode = modeX509
	}

	// Fields common to both modes.
	data := map[string]any{
		"mode":            mode,
		"token_ttl":       b.config.TokenTTL.String(),
		"revocation_mode": b.config.RevocationMode,
		"crl_cache_ttl":   b.config.CRLCacheTTL,
		"ocsp_timeout":    b.config.OCSPTimeout,
		"default_role":    b.config.DefaultRole,
	}

	// x509-only fields are surfaced only in x509 mode; in spiffe mode trust
	// domains are managed and listed under spiffe/trust-domain/.
	if mode == modeX509 {
		certCount := 0
		if b.config.TrustedCAPEM != "" {
			certCount = parsePEMCertificates(b.config.TrustedCAPEM)
		}
		data["trusted_ca_pem"] = b.config.TrustedCAPEM
		data["principal_claim"] = b.config.PrincipalClaim
		data["trusted_ca_count"] = certCount
	}

	return &logical.Response{StatusCode: http.StatusOK, Data: data}, nil
}

// handleConfigWrite handles writing the configuration
func (b *certAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Reject the removed "spiffe_id" principal claim on new writes. A persisted
	// legacy value is coerced to "uri_san" on load instead (see setupCertConfig).
	if v, ok := d.GetOk("principal_claim"); ok {
		if claim, _ := v.(string); claim == "spiffe_id" {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        fmt.Errorf("principal_claim \"spiffe_id\" is no longer supported; configure a mount with mode=spiffe for SPIFFE SVID validation"),
			}, nil
		}
	}

	// Resolve current vs requested mode and enforce mode coherence.
	b.configMu.RLock()
	currentMode := modeX509
	if b.config != nil && b.config.Mode != "" {
		currentMode = b.config.Mode
	}
	b.configMu.RUnlock()

	effectiveMode := currentMode
	if v, ok := d.GetOk("mode"); ok {
		if requested, _ := v.(string); requested != "" {
			effectiveMode = requested
			if requested != currentMode {
				// Switching mode would orphan existing roles/trust domains into an
				// incompatible mount; require a clean slate.
				roles, err := b.listRoles(ctx)
				if err != nil {
					return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
				}
				tds, err := b.listTrustDomains(ctx)
				if err != nil {
					return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
				}
				if len(roles) > 0 || len(tds) > 0 {
					return &logical.Response{
						StatusCode: http.StatusBadRequest,
						Err:        fmt.Errorf("cannot change mode while roles or trust domains exist; delete them first or use a new mount"),
					}, nil
				}
			}
		}
	}

	// PKI-only config fields are not accepted in spiffe mode.
	if effectiveMode == modeSPIFFE {
		if _, ok := d.GetOk("trusted_ca_pem"); ok {
			return &logical.Response{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("trusted_ca_pem is not allowed in spiffe mode; configure trust domains via spiffe/trust-domain/<name>")}, nil
		}
		if _, ok := d.GetOk("principal_claim"); ok {
			return &logical.Response{StatusCode: http.StatusBadRequest, Err: fmt.Errorf("principal_claim is not allowed in spiffe mode; the principal is the verified SVID ID")}, nil
		}
	}

	// Build config map from field data
	conf := make(map[string]any)

	// Copy existing config if present
	b.configMu.RLock()
	if b.config != nil {
		conf["mode"] = b.config.Mode
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

	// In spiffe mode, drop any carried-over PKI-only fields so the persisted
	// config stays coherent with the mode.
	if effectiveMode == modeSPIFFE {
		delete(conf, "trusted_ca_pem")
		delete(conf, "principal_claim")
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
			"mode":            b.config.Mode,
			"trusted_ca_pem":  b.config.TrustedCAPEM,
			"principal_claim": b.config.PrincipalClaim,
			"token_ttl":       b.config.TokenTTL.String(),
			"revocation_mode": b.config.RevocationMode,
			"crl_cache_ttl":   b.config.CRLCacheTTL,
			"ocsp_timeout":    b.config.OCSPTimeout,
			"default_role":    b.config.DefaultRole,
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
