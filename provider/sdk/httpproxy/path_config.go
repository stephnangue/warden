package httpproxy

import (
	"context"
	"net/http"
	"strings"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathConfig returns the config path definition for the provider.
func (b *proxyBackend) pathConfig() *framework.Path {
	fields := map[string]*framework.FieldSchema{
		b.spec.URLConfigKey: {
			Type:        framework.TypeString,
			Description: "The upstream API base URL (default: " + b.spec.DefaultURL + ")",
			Default:     b.spec.DefaultURL,
		},
		"max_body_size": {
			Type:        framework.TypeInt64,
			Description: "Maximum request body size in bytes (default: 10MB, max: 100MB)",
			Default:     framework.DefaultMaxBodySize,
		},
		"timeout": {
			Type:        framework.TypeDurationSecond,
			Description: "Request timeout duration (e.g., '120s', '5m')",
			Default:     b.spec.DefaultTimeout.String(),
		},
		"auto_auth_path": {
			Type:        framework.TypeString,
			Description: "Path to auth mount for implicit authentication (e.g., 'auth/jwt/', 'auth/cert/')",
		},
		"default_role": {
			Type:        framework.TypeString,
			Description: "Default role to use when not specified in URL path",
		},
		"user_auth_path": {
			Type:        framework.TypeString,
			Description: "Auth mount that authenticates the secondary (user) principal from a second request header (bearer/JWT format required)",
		},
		"user_auth_role": {
			Type:        framework.TypeString,
			Description: "Role used to authenticate the user credential (default: the user auth mount's own default_role)",
		},
		"tls_skip_verify": {
			Type:        framework.TypeBool,
			Description: "Skip TLS certificate verification (for dev/test clusters)",
			Default:     false,
		},
		"ca_data": {
			Type:        framework.TypeString,
			Description: "Base64-encoded PEM CA certificate for custom certificate authorities",
		},
	}

	// Merge extra config fields from spec
	for k, v := range b.spec.ExtraConfigFields {
		fields[k] = v
	}

	return &framework.Path{
		Pattern: "config",
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read " + b.spec.Name + " provider configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure " + b.spec.Name + " provider settings",
			},
		},
		HelpSynopsis:    "Configure " + b.spec.Name + " provider",
		HelpDescription: "This endpoint configures the " + b.spec.Name + " provider settings including API URL, body size limits, and timeouts.",
	}
}

// handleConfigRead handles reading the provider configuration.
func (b *proxyBackend) handleConfigRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tc := b.TransparentConfig()
	b.mu.RLock()
	data := map[string]any{
		b.spec.URLConfigKey: b.providerURL,
		"max_body_size":     b.MaxBodySize(),
		"timeout":           b.Timeout().String(),
		"auto_auth_path":    tc.AutoAuthPath,
		"default_role":      tc.DefaultAuthRole,
		"user_auth_path":    tc.UserAuthPath,
		"user_auth_role":    tc.UserAuthRole,
		"tls_skip_verify":   b.tlsSkipVerify,
		"ca_data":           b.caData,
	}

	// Add extra fields from provider state
	if b.spec.OnConfigRead != nil {
		extra := b.spec.OnConfigRead(b.extraState)
		for k, v := range extra {
			data[k] = v
		}
	}
	b.mu.RUnlock()

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       data,
	}, nil
}

// handleConfigWrite handles writing the provider configuration.
//
// A write changes nothing until it has succeeded: every value is validated and
// built — the transport and the provider's extra state included — into locals,
// persisted, and only then applied, so a rejected write leaves the running
// configuration exactly as it was, and a storage failure leaves it matching
// storage. Writes are serialized, so each one works from the configuration
// the previous one left.
func (b *proxyBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configWriteMu.Lock()
	defer b.configWriteMu.Unlock()

	// One snapshot of the provider-local fields this write builds on. The
	// extra state is cloned, so OnConfigWrite may mutate its input in place:
	// the live map is read concurrently by gateway-path code (DynamicHeaders,
	// ResolveUpstream).
	b.mu.RLock()
	oldURL := b.providerURL
	oldSkipVerify := b.tlsSkipVerify
	oldCAData := b.caData
	extraState := cloneExtraState(b.extraState)
	b.mu.RUnlock()

	// Read tls_skip_verify before URL validation so HTTP can be conditionally allowed
	skipVerify := oldSkipVerify
	if val, ok := d.GetOk("tls_skip_verify"); ok {
		skipVerify = val.(bool)
	}

	var newURL string
	if val, ok := d.GetOk(b.spec.URLConfigKey); ok {
		addr := val.(string)
		if addr != "" {
			addr = strings.TrimRight(addr, "/")
			if err := framework.ValidateURL(addr, b.spec.URLConfigKey, skipVerify); err != nil {
				return &logical.Response{
					StatusCode: http.StatusBadRequest,
					Err:        logical.ErrBadRequest(err.Error()),
				}, nil
			}
			newURL = addr
		}
	}

	// Validate max_body_size bounds
	var newMaxBodySize int64
	var hasMaxBodySize bool
	if val, ok := d.GetOk("max_body_size"); ok {
		newMaxBodySize = val.(int64)
		hasMaxBodySize = true
		if newMaxBodySize <= 0 {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest("max_body_size must be greater than 0"),
			}, nil
		}
		if newMaxBodySize > 104857600 { // 100MB
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest("max_body_size must not exceed 104857600 bytes (100MB)"),
			}, nil
		}
	}

	var newTimeout time.Duration
	var hasTimeout bool
	if val, ok := d.GetOk("timeout"); ok {
		newTimeout = time.Duration(val.(int)) * time.Second
		hasTimeout = true
	}

	// Transparent mode settings — TransparentConfig() is atomic, no lock needed.
	current := b.TransparentConfig()
	tc := &framework.TransparentConfig{
		AutoAuthPath:    current.AutoAuthPath,
		DefaultAuthRole: current.DefaultAuthRole,
		UserAuthPath:    current.UserAuthPath,
		UserAuthRole:    current.UserAuthRole,
	}
	if val, ok := d.GetOk("auto_auth_path"); ok {
		tc.AutoAuthPath = val.(string)
	}
	if val, ok := d.GetOk("default_role"); ok {
		tc.DefaultAuthRole = val.(string)
	}
	if val, ok := d.GetOk("user_auth_path"); ok {
		tc.UserAuthPath = val.(string)
	}
	if val, ok := d.GetOk("user_auth_role"); ok {
		tc.UserAuthRole = val.(string)
	}

	if tc.AutoAuthPath == "" {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest("auto_auth_path is required"),
		}, nil
	}

	// Validate the secondary (user) auth config: types and the
	// user_auth_role → user_auth_path dependency. The bearer-format check on
	// the referenced mount is enforced at runtime (fail closed).
	if err := framework.ValidateUserAuthConfig(map[string]any{
		"user_auth_path": tc.UserAuthPath,
		"user_auth_role": tc.UserAuthRole,
	}); err != nil {
		return &logical.Response{
			StatusCode: http.StatusBadRequest,
			Err:        logical.ErrBadRequest(err.Error()),
		}, nil
	}

	// Process TLS settings, compared against the snapshot
	newSkipVerify := oldSkipVerify
	newCAData := oldCAData
	tlsChanged := false
	if val, ok := d.GetOk("tls_skip_verify"); ok {
		newSkipVerify = val.(bool)
		if newSkipVerify != oldSkipVerify {
			tlsChanged = true
		}
	}
	if val, ok := d.GetOk("ca_data"); ok {
		newCAData = val.(string)
		if newCAData != oldCAData {
			tlsChanged = true
		}
	}

	var newTransport *http.Transport
	if tlsChanged {
		var err error
		newTransport, err = NewTransportWithTLS(newCAData, newSkipVerify)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest(err.Error()),
			}, nil
		}
	}

	// The provider's extra config fields, into the cloned state. A refusal
	// here is a 400 like any other, before anything has changed.
	newState := extraState
	if b.spec.OnConfigWrite != nil {
		var err error
		newState, err = b.spec.OnConfigWrite(d, extraState)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusBadRequest,
				Err:        logical.ErrBadRequest(err.Error()),
			}, nil
		}
	}

	// The values this write leaves in force.
	providerURL := oldURL
	if newURL != "" {
		providerURL = newURL
	}
	maxBodySize := b.MaxBodySize()
	if hasMaxBodySize {
		maxBodySize = newMaxBodySize
	} else if maxBodySize == 0 {
		maxBodySize = framework.DefaultMaxBodySize
	}
	timeout := b.Timeout()
	if hasTimeout {
		timeout = newTimeout
	} else if timeout == 0 {
		timeout = b.spec.DefaultTimeout
	}

	configData := map[string]any{
		b.spec.URLConfigKey: providerURL,
		"max_body_size":     maxBodySize,
		"timeout":           timeout.String(),
		"auto_auth_path":    tc.AutoAuthPath,
		"default_role":      tc.DefaultAuthRole,
		"user_auth_path":    tc.UserAuthPath,
		"user_auth_role":    tc.UserAuthRole,
		"tls_skip_verify":   newSkipVerify,
		"ca_data":           newCAData,
	}
	if b.spec.OnConfigRead != nil {
		for k, v := range b.spec.OnConfigRead(newState) {
			configData[k] = v
		}
	}

	// Persist config to storage
	if b.StorageView != nil {
		entry, err := sdklogical.StorageEntryJSON("config", configData)
		if err != nil {
			return &logical.Response{
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}, nil
		}
		if err := b.StorageView.Put(ctx, entry); err != nil {
			return &logical.Response{
				StatusCode: http.StatusInternalServerError,
				Err:        err,
			}, nil
		}
	}

	// Apply. Nothing below can fail. Framework-side fields are atomic;
	// provider-local ones go under the write lock.
	b.SetMaxBodySize(maxBodySize)
	b.SetTimeout(timeout)
	b.mu.Lock()
	b.providerURL = providerURL
	if tlsChanged {
		b.tlsSkipVerify = newSkipVerify
		b.caData = newCAData
		b.SetTransport(newTransport)
	}
	b.StreamingBackend.SetTransparentConfig(tc)
	b.extraState = newState
	b.mu.Unlock()

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"message": "configuration updated",
		},
	}, nil
}
