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
		"bound_audiences": {
			Type: framework.TypeCommaStringSlice,
			Description: "Audiences a JWT-SVID must carry, any one of them. Required when entity_kind is agent; " +
				"X.509-SVIDs carry no audience. No entry may be empty.",
		},
		"max_age": {
			Type: framework.TypeDurationSecond,
			Description: "Maximum age of an SVID at admission, measured from its issue time (iat): a duration such as 10m, " +
				"or a number of seconds. Applies to JWT-SVIDs; X.509-SVIDs carry no issue time and are not checked. " +
				"JWT-SVIDs older than max_age, or without an issue time, are not admitted. " +
				"0 or empty leaves it unset.",
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
		HelpDescription: `Mount-level defaults. Trust domains are managed under trust-domain/.

'entity_kind' (agent or human, default agent) names what the mount admits.
'facts' maps SVID fields to the fact names the mount publishes beyond its
built-in facts (aud, path, spiffe_id, svid, trust_domain; svid is x509 or jwt,
and aud holds a JWT-SVID's audiences); a write replaces the whole map.
'bound_audiences' are the audiences a JWT-SVID must carry; required on a mount
that admits agents.
'max_age' bounds a JWT-SVID's age at admission, from its iat: a JWT-SVID older
than it, or without an iat, is not admitted. It applies to JWT-SVIDs;
X.509-SVIDs carry no issue time and are not checked.`,
	}
}

// unconfigured is what a mount with no config runs with, as a config read
// renders it: the agent kind with the built-in facts only (the naming Factory
// publishes), no audiences, no max_age, and a token_ttl of zero, which
// calculateTTL reads as no cap from the mount (the SVID's lifetime still
// applies). It is never written, so reads share it without a lock.
var unconfigured = &SPIFFEAuthConfig{FactsConfig: helper.FactsConfig{EntityKind: logical.EntityKindAgent}}

func (b *spiffeAuthBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	config := b.config
	if config == nil {
		config = unconfigured
	}
	data := map[string]any{
		"token_ttl":       config.TokenTTL.String(),
		"bound_audiences": slices.Clone(config.BoundAudiences),
		"max_age":         config.MaxAge.String(),
		"entity_kind":     config.EntityKind,
		"facts":           maps.Clone(config.Facts),
	}
	helper.SetWarnings(data, helper.RemovedConfigWarnings(config.removed))
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       data,
	}, nil
}

// handleConfigWrite builds the merged config, persists it, and only then
// installs it, so a write that is refused or cannot be stored leaves the mount
// on what storage holds. Writes are serialized, so each merges onto the
// configuration the previous one left.
func (b *spiffeAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	// Keys of the role era are refused, not ignored: the write would otherwise
	// succeed while doing nothing the operator asked for. The stored config
	// never carries them, so this write also removes any it still did.
	if err := helper.RefuseRemovedConfigKeys(d.Raw); err != nil {
		return logical.ErrorResponse(err), nil
	}

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
		conf["bound_audiences"] = b.config.BoundAudiences
		conf["max_age"] = b.config.MaxAge
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
	// An agent mount binds an audience; a stored config without one admits
	// no JWT-SVID, and a write cannot create one.
	if helper.RequireAgentAudiences(config.EntityKind, config.BoundAudiences) != nil {
		return &logical.Response{StatusCode: http.StatusBadRequest, Err: helper.AgentAudiencesWriteError()}, nil
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
