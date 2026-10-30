package oidc

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func (b *oidcAuthBackend) pathConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{
		"oidc_discovery_url": {
			Type:        framework.TypeString,
			Description: "Issuer URL of the identity provider; discovery reads <url>/.well-known/openid-configuration, and ID tokens must carry it as iss.",
		},
		"oidc_discovery_ca_pem": {
			Type:        framework.TypeString,
			Description: "PEM CA certificate the identity provider's TLS chains to, when not a public one.",
		},
		"client_id": {
			Type:        framework.TypeString,
			Description: "Client ID of Warden's registration at the identity provider; ID tokens must carry it as aud.",
		},
		"client_auth": {
			Type:        framework.TypeString,
			Description: "How Warden authenticates at the token endpoint: client_secret (default), private_key_jwt or none.",
		},
		"client_secret": {
			Type:        framework.TypeString,
			Description: "Client secret, for client_auth client_secret. Never read back.",
		},
		"private_key": {
			Type:        framework.TypeString,
			Description: "PEM RSA private key signing the client assertion, for client_auth private_key_jwt. Never read back.",
		},
		"client_certificate": {
			Type: framework.TypeString,
			Description: "PEM certificate of the private key, for client_auth private_key_jwt: its SHA-256 thumbprint is sent " +
				"as the assertion's x5t#S256 header, for an identity provider that identifies the key by its certificate.",
		},
		"client_assertion_kid": {
			Type:        framework.TypeString,
			Description: "Key ID the identity provider knows the private key by, sent as the assertion's kid.",
		},
		"supported_algs": {
			Type:        framework.TypeCommaStringSlice,
			Description: "ID token signing algorithms accepted (default RS256).",
		},
		"allowed_redirect_uris": {
			Type: framework.TypeCommaStringSlice,
			Description: "Redirect URIs a login may use, matched exactly; a loopback URI (127.0.0.1, ::1, localhost) " +
				"matches on any port. warden login uses http://localhost:8251/oidc/callback by default; " +
				"http://localhost/oidc/callback here allows it on any port.",
		},
		"scopes": {
			Type:        framework.TypeCommaStringSlice,
			Description: "Scopes requested (default openid, profile); openid is required.",
		},
		"session_ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Lifetime of the session a login issues (default 1h, at most 8h). It cannot be revoked before.",
		},
	}
	maps.Copy(fields, helper.FactsFieldSchemas("an ID token claim name, or a JSON Pointer with a leading / into nested claims", aliasSources))

	return &framework.Path{
		Pattern: "config",
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read the oidc auth configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure the oidc auth method",
			},
		},
		HelpSynopsis: "Configure the oidc auth method",
		HelpDescription: `Configures the identity provider people sign in with.

Discovery runs at oidc_discovery_url when the configuration is written, and the
issuer the provider publishes must equal it. 'facts' maps ID token claims to
the fact names virtual groups match, beyond the built-in sub, iss and aud;
'alias_name_source' names the fact a person's identity is taken from.
client_secret and private_key are never read back.`,
	}
}

func (b *oidcAuthBackend) handleConfigRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()
	c := b.config
	if c == nil {
		return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{}}, nil
	}
	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{
		"oidc_discovery_url":    c.OIDCDiscoveryURL,
		"oidc_discovery_ca_pem": c.OIDCDiscoveryCA,
		"client_id":             c.ClientID,
		"client_auth":           c.ClientAuth,
		"client_certificate":    c.ClientCertificate,
		"client_assertion_kid":  c.ClientAssertionKID,
		"supported_algs":        slices.Clone(c.SupportedAlgs),
		"allowed_redirect_uris": slices.Clone(c.AllowedRedirectURIs),
		"scopes":                slices.Clone(c.Scopes),
		"session_ttl":           c.SessionTTL.String(),
		"entity_kind":           c.EntityKind,
		"facts":                 maps.Clone(c.Facts),
		"alias_name_source":     c.AliasNameSource,
	}}, nil
}

// handleConfigWrite merges the request onto the live configuration, validates
// it, runs discovery, persists it and only then installs it, so a refused or
// unstorable write leaves the mount as it was. Writes are serialized. A
// secret not sent is kept; a change of client_auth drops the client secret,
// private key and certificate unless the write sends them. A write over an
// invalid stored config replaces it.
func (b *oidcAuthBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	var next oidcConfig
	b.configMu.RLock()
	if b.config != nil {
		next = *b.config
		next.SupportedAlgs = slices.Clone(next.SupportedAlgs)
		next.AllowedRedirectURIs = slices.Clone(next.AllowedRedirectURIs)
		next.Scopes = slices.Clone(next.Scopes)
		next.Facts = maps.Clone(next.Facts)
		next.privateKey, next.x5tS256, next.invalid = nil, "", nil
	}
	b.configMu.RUnlock()

	str := func(key string, dst *string) {
		if v, ok := d.GetOk(key); ok {
			*dst = v.(string)
		}
	}
	list := func(key string, dst *[]string) {
		if v, ok := d.GetOk(key); ok {
			*dst = v.([]string)
		}
	}
	str("oidc_discovery_url", &next.OIDCDiscoveryURL)
	str("oidc_discovery_ca_pem", &next.OIDCDiscoveryCA)
	str("client_id", &next.ClientID)
	if v, ok := d.GetOk("client_auth"); ok && v.(string) != next.ClientAuth {
		next.ClientAuth = v.(string)
		next.ClientSecret, next.PrivateKey, next.ClientCertificate = "", "", ""
	}
	str("client_secret", &next.ClientSecret)
	str("private_key", &next.PrivateKey)
	str("client_certificate", &next.ClientCertificate)
	str("client_assertion_kid", &next.ClientAssertionKID)
	list("supported_algs", &next.SupportedAlgs)
	list("allowed_redirect_uris", &next.AllowedRedirectURIs)
	list("scopes", &next.Scopes)
	if v, ok := d.GetOk("session_ttl"); ok {
		// 0 restores the default.
		next.SessionTTL = time.Duration(v.(int)) * time.Second
	}
	_, factsSent := d.GetOk("facts")
	_, kindSent := d.GetOk("entity_kind")
	_, aliasSent := d.GetOk("alias_name_source")
	str("entity_kind", &next.EntityKind)
	if raw, ok := d.GetOk("facts"); ok {
		facts, err := helper.ParseFactsField(raw)
		if err != nil {
			return badRequest(err), nil
		}
		next.Facts = facts
	}
	if raw, ok := d.GetOk("alias_name_source"); ok {
		source, err := helper.ParseAliasNameSource(raw)
		if err != nil {
			return badRequest(err), nil
		}
		next.AliasNameSource = source
	}

	if err := next.validate(); err != nil {
		return badRequest(err), nil
	}
	if err := helper.FactsWriteError(&next.FactsConfig, factsSent || kindSent || aliasSent); err != nil {
		return badRequest(err), nil
	}
	p, err := next.newProvider(ctx)
	if err != nil {
		return badRequest(err), nil
	}

	if b.storageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", &next)
		if err == nil {
			err = b.storageView.Put(ctx, entry)
		}
		if err != nil {
			p.Done()
			return &logical.Response{StatusCode: http.StatusInternalServerError, Err: err}, nil
		}
	}
	b.installConfig(&next, p)
	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"message": "configuration updated"}}, nil
}

func badRequest(err error) *logical.Response {
	return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}
}
