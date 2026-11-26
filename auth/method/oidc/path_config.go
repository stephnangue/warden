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
		"dpop_enabled": {
			Type: framework.TypeBool,
			Description: "Bind every session to a key the warden CLI holds, proven on every request (default true). " +
				"Off, sessions are bearer tokens other tools can present. A change applies from the next login.",
		},
		"mfa_options": {
			Type: framework.TypeMap,
			Description: "What every sign-in must meet. require: facts the ID token must hold, as a group rule's " +
				"selectors (fact name to accepted values; every fact must match, by any one value), asked of the " +
				"identity provider at login. reauthenticate_after: how long after the person signed in a session " +
				"ends (5m to 8h); each login asks for a new sign-in. Checked at login and on every request, so a " +
				"change applies to sessions already issued. A write replaces the whole object; an empty object clears it.",
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
'mfa_options' holds every sign-in to a floor over those facts ('require') and
ends sessions a set time after the person signed in ('reauthenticate_after').
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
		"dpop_enabled":          c.dpop(),
		"entity_kind":           c.EntityKind,
		"facts":                 maps.Clone(c.Facts),
		"alias_name_source":     c.AliasNameSource,
		"mfa_options":           mfaOptionsData(c.MFAOptions),
	}}, nil
}

// mfaOptionsData renders mfa_options as a read returns them: the keys set,
// reauthenticate_after as a duration string; an empty object when unset.
func mfaOptionsData(o *helper.MFAOptions) map[string]any {
	out := map[string]any{}
	if o == nil {
		return out
	}
	if len(o.Require) > 0 {
		require := make(map[string][]string, len(o.Require))
		for name, values := range o.Require {
			require[name] = slices.Clone(values)
		}
		out["require"] = require
	}
	if o.ReauthenticateAfter > 0 {
		out["reauthenticate_after"] = o.ReauthenticateAfter.String()
	}
	return out
}

// handleConfigWrite merges the request onto the live configuration, validates
// it, runs discovery, persists it and only then installs it, so a refused or
// unstorable write leaves the mount as it was. Writes are serialized. A
// secret not sent is kept; a change of client_auth drops the client secret,
// private key and certificate unless the write sends them. A write over an
// invalid stored config replaces it. A sent mfa_options replaces the stored
// block whole, and an empty object clears it; a write that drops a stored part
// (require, reauthenticate_after) succeeds with a warning saying so.
func (b *oidcAuthBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	var next oidcConfig
	wasBinding := false
	var hadMFA *helper.MFAOptions
	b.configMu.RLock()
	if b.config != nil {
		wasBinding = b.config.dpop()
		hadMFA = b.config.MFAOptions
		// The stored mfa_options are shared, not copied: a config never
		// modifies them, and a write that sends the key replaces them whole.
		next = *b.config
		next.SupportedAlgs = slices.Clone(next.SupportedAlgs)
		next.AllowedRedirectURIs = slices.Clone(next.AllowedRedirectURIs)
		next.Scopes = slices.Clone(next.Scopes)
		next.Facts = maps.Clone(next.Facts)
		next.privateKey, next.x5tS256, next.invalid, next.signIn = nil, "", nil, nil
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
	if v, ok := d.GetOk("dpop_enabled"); ok {
		on := v.(bool)
		next.DPoPEnabled = &on
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
	// Parsed from the raw value: the field's decoding reads null and [] as an
	// empty object, which would clear the block. Only {} clears it.
	raw, mfaSent := d.Raw["mfa_options"]
	if mfaSent {
		o, err := helper.ParseMFAOptions(raw)
		if err != nil {
			return badRequest(err), nil
		}
		next.MFAOptions = o
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
	resp := &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"message": "configuration updated"}}
	var warnings []string
	if wasBinding && !next.dpop() {
		warnings = append(warnings, "sessions this mount already issued stay bound to their keys until they expire "+
			"(at most session_ttl); sessions from the next login on are bearer tokens")
	}
	if mfaSent {
		warnings = append(warnings, mfaDropWarnings(hadMFA, next.MFAOptions)...)
		warnings = append(warnings, next.MFAOptions.Warnings()...)
	}
	if len(warnings) > 0 {
		// In the data, where clients read warnings (the HTTP layer writes no
		// other), and in Warnings, which the audit records.
		resp.Data["warnings"] = warnings
		for _, w := range warnings {
			resp.AddWarning(w)
		}
	}
	return resp, nil
}

// mfaDropWarnings returns the warnings of a write that replaces the stored
// mfa_options prev with next: one for each part prev set and next drops, since
// a write replaces the block whole and an edit of one part can drop the other
// unseen.
func mfaDropWarnings(prev, next *helper.MFAOptions) []string {
	if prev == nil {
		return nil
	}
	var out []string
	if len(prev.Require) > 0 && (next == nil || len(next.Require) == 0) {
		out = append(out, "mfa_options.require is removed: sign-ins are no longer held to a floor; "+
			"send require in mfa_options to keep one")
	}
	if prev.ReauthenticateAfter > 0 && (next == nil || next.ReauthenticateAfter == 0) {
		out = append(out, "mfa_options.reauthenticate_after is removed: sessions last session_ttl whenever "+
			"the person signed in; send reauthenticate_after in mfa_options to keep it")
	}
	return out
}

func badRequest(err error) *logical.Response {
	return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}
}
