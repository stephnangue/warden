package spiffe

import (
	"context"
	"net/http"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

func (b *spiffeAuthBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default token TTL (default: 1h)",
			},
			"default_role": {
				Type:        framework.TypeString,
				Description: "Default role for transparent operations when no role is specified",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleConfigRead, Summary: "Read SPIFFE auth configuration"},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleConfigWrite, Summary: "Configure SPIFFE authentication"},
		},
		HelpSynopsis:    "Configure SPIFFE authentication",
		HelpDescription: "Mount-level defaults. Trust domains are managed under trust-domain/, and roles under role/.",
	}
}

func (b *spiffeAuthBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configMu.RLock()
	defer b.configMu.RUnlock()

	if b.config == nil {
		return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{}}, nil
	}
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"token_ttl":    b.config.TokenTTL.String(),
			"default_role": b.config.DefaultRole,
		},
	}, nil
}

func (b *spiffeAuthBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	conf := make(map[string]any)

	b.configMu.RLock()
	if b.config != nil {
		conf["token_ttl"] = b.config.TokenTTL
		conf["default_role"] = b.config.DefaultRole
	}
	b.configMu.RUnlock()

	for key := range d.Schema {
		if val, ok := d.GetOk(key); ok {
			conf[key] = val
		}
	}

	if err := b.setupSPIFFEConfig(ctx, conf); err != nil {
		return &logical.Response{StatusCode: http.StatusBadRequest, Err: err}, nil
	}

	// Persist normalized config so a restart parses consistent types.
	if b.storageView != nil {
		b.configMu.RLock()
		normalized := map[string]any{
			"token_ttl":    b.config.TokenTTL.String(),
			"default_role": b.config.DefaultRole,
		}
		b.configMu.RUnlock()

		entry, err := sdklogical.StorageEntryJSON("config", normalized)
		if err != nil {
			return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
		}
		if err := b.storageView.Put(ctx, entry); err != nil {
			return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
		}
	}

	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"message": "configuration updated"}}, nil
}
