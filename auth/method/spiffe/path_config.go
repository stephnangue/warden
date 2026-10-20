package spiffe

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

func (b *spiffeAuthBackend) pathConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{
		"token_ttl": {
			Type:        framework.TypeDurationSecond,
			Description: "Default token TTL (default: 1h)",
		},
		"default_role": {
			Type:        framework.TypeString,
			Description: "Default role for transparent operations when no role is specified",
		},
		"bound_audiences": {
			Type: framework.TypeCommaStringSlice,
			Description: "Audiences a JWT-SVID must carry, any one of them. Stored for mount-level audience binding; " +
				"logins do not use it yet (a role's bound_audiences still applies). " +
				"No entry may be empty; an empty value clears the list.",
		},
	}
	maps.Copy(fields, helper.FactsFieldSchemas(factsSources))

	return &framework.Path{
		Pattern: "config",
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleConfigRead, Summary: "Read SPIFFE auth configuration"},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleConfigWrite, Summary: "Configure SPIFFE authentication"},
		},
		HelpSynopsis: "Configure SPIFFE authentication",
		HelpDescription: `Mount-level defaults. Trust domains are managed under trust-domain/, and roles under role/.

'entity_kind' (agent or human, default agent) names what the mount admits.
'facts' maps SVID fields to the fact names the mount publishes beyond its
built-in facts (aud, path, spiffe_id, svid, trust_domain; svid is x509 or jwt,
and aud holds a JWT-SVID's audiences); a write replaces the whole map.
'bound_audiences' is stored for mount-level audience binding and not used by
logins yet.`,
	}
}

// unconfigured is what a mount with no config runs with, as a config read
// renders it: the agent kind with the built-in facts only (the naming Factory
// publishes), no audiences, no default role, and a token_ttl of zero, which
// calculateTTL reads as no cap from the mount (the role's TTL and the SVID's
// lifetime still apply). It is never written, so reads share it without a
// lock.
var unconfigured = &SPIFFEAuthConfig{FactsConfig: helper.FactsConfig{EntityKind: logical.EntityKindAgent}}

func (b *spiffeAuthBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	config := b.config
	if config == nil {
		config = unconfigured
	}
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"token_ttl":       config.TokenTTL.String(),
			"default_role":    config.DefaultRole,
			"bound_audiences": slices.Clone(config.BoundAudiences),
			"entity_kind":     config.EntityKind,
			"facts":           maps.Clone(config.Facts),
		},
	}, nil
}

// handleConfigWrite builds the merged config, persists it, and only then
// installs it, so a write that is refused or cannot be stored leaves the mount
// on what storage holds. Writes are serialized, so each merges onto the
// configuration the previous one left.
func (b *spiffeAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	conf := make(map[string]any)

	_, factsSent := d.GetOk("facts")
	_, kindSent := d.GetOk("entity_kind")
	factsTouched := factsSent || kindSent

	b.configMu.RLock()
	if b.config != nil {
		// Stored facts that do not compile would fail a write that leaves
		// them in place, whatever else it changes; say how to replace them.
		if !factsTouched {
			if err := helper.FactsWriteError(&b.config.FactsConfig, false); err != nil {
				b.configMu.RUnlock()
				return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}, nil
			}
		}
		conf["token_ttl"] = b.config.TokenTTL
		conf["default_role"] = b.config.DefaultRole
		conf["bound_audiences"] = b.config.BoundAudiences
		conf["entity_kind"] = b.config.EntityKind
		conf["facts"] = b.config.Facts
	}
	b.configMu.RUnlock()

	for key := range d.Schema {
		if val, ok := d.GetOk(key); ok {
			conf[key] = val
		}
	}

	// A facts write replaces the whole mapping; every name must be a string.
	if raw, ok := d.GetOk("facts"); ok {
		facts, err := helper.ParseFactsField(raw)
		if err != nil {
			return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}, nil
		}
		conf["facts"] = facts
	}

	config, err := buildSPIFFEConfig(conf)
	if err != nil {
		return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}, nil
	}
	// A write is the one place facts can be refused outright; storage and
	// load only ever see a config that compiled here.
	if err := helper.FactsWriteError(&config.FactsConfig, factsTouched); err != nil {
		return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}, nil
	}

	// Persist normalized config before installing it.
	if b.storageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", normalizedSPIFFEConfig(config))
		if err != nil {
			return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
		}
		if err := b.storageView.Put(ctx, entry); err != nil {
			return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
		}
	}

	b.installConfig(config)

	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"message": "configuration updated"}}, nil
}
