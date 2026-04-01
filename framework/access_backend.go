package framework

import (
	"context"
	"encoding/json"
	"strings"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// AccessConfig holds the implicit auth configuration for access backends.
type AccessConfig struct {
	AutoAuthPath string `json:"auto_auth_path"`
}

// AccessBackend implements logical.Backend for access backends that vend access grants
// (connection strings, presigned URLs, etc.) without proxying traffic.
// It provides implicit auth support and storage access, paralleling StreamingBackend
// for proxy providers.
type AccessBackend struct {
	*Backend

	// Logger is the provider's scoped logger.
	Logger *logger.GatedLogger

	// StorageView is the provider's storage backend for persisting configuration.
	StorageView sdklogical.Storage

	// AccessPathPrefix is the path prefix that triggers transparent auth.
	// Defaults to "access/" if empty.
	AccessPathPrefix string

	// cfg holds the persisted implicit auth configuration.
	cfg *AccessConfig
}

// Compile-time interface assertions
var _ logical.Backend = (*AccessBackend)(nil)
var _ logical.TransparentModeProvider = (*AccessBackend)(nil)

// Setup initializes the access backend with the provided configuration.
// It loads persisted config from storage.
func (b *AccessBackend) Setup(ctx context.Context, conf *logical.BackendConfig) error {
	b.StorageView = conf.StorageView
	if b.Logger == nil {
		b.Logger = conf.Logger
	}
	if err := b.Backend.Setup(ctx, conf); err != nil {
		return err
	}
	b.cfg = &AccessConfig{}
	b.loadConfig(ctx)
	return nil
}

// --- TransparentModeProvider implementation ---

// IsTransparentMode returns whether the backend has an auth path configured.
func (b *AccessBackend) IsTransparentMode() bool {
	return b.cfg != nil && b.cfg.AutoAuthPath != ""
}

// GetAutoAuthPath returns the auth mount path for implicit authentication.
func (b *AccessBackend) GetAutoAuthPath() string {
	if b.cfg == nil {
		return ""
	}
	return b.cfg.AutoAuthPath
}

// GetAuthRole extracts the auth role from the ?role= query parameter.
// Falls back to empty string (auth method's default_role provides the fallback).
func (b *AccessBackend) GetAuthRole(_ string, req *logical.Request) string {
	if req != nil {
		if role, ok := req.Data["role"].(string); ok {
			return role
		}
	}
	return ""
}

// IsTransparentPath checks if the given path should trigger transparent authentication.
// Matches paths starting with the configured access path prefix (default "access/").
func (b *AccessBackend) IsTransparentPath(path string) bool {
	prefix := b.AccessPathPrefix
	if prefix == "" {
		prefix = "access/"
	}
	return strings.HasPrefix(path, prefix)
}

// IsUnauthenticatedPath returns false — all access paths require authentication.
func (b *AccessBackend) IsUnauthenticatedPath(path string) bool {
	return false
}

// --- Config persistence ---

// GetAccessConfig returns the current access configuration.
func (b *AccessBackend) GetAccessConfig() *AccessConfig {
	if b.cfg == nil {
		return &AccessConfig{}
	}
	return b.cfg
}

// SetAccessConfig updates and persists the access configuration.
func (b *AccessBackend) SetAccessConfig(ctx context.Context, cfg *AccessConfig) error {
	b.cfg = cfg
	entry, err := sdklogical.StorageEntryJSON("access_config", cfg)
	if err != nil {
		return err
	}
	return b.StorageView.Put(ctx, entry)
}

// loadConfig loads persisted access configuration from storage.
func (b *AccessBackend) loadConfig(ctx context.Context) {
	if b.StorageView == nil {
		return
	}
	entry, err := b.StorageView.Get(ctx, "access_config")
	if err != nil || entry == nil {
		return
	}
	var cfg AccessConfig
	if err := json.Unmarshal(entry.Value, &cfg); err != nil {
		return
	}
	b.cfg = &cfg
}

// PathAccessConfig returns a standard config path for access backends.
// Providers can include this in their paths() to get config CRUD for free.
func (b *AccessBackend) PathAccessConfig() *Path {
	return &Path{
		Pattern: "config",
		Fields: map[string]*FieldSchema{
			"auto_auth_path": {
				Type:        TypeString,
				Description: "Auth mount path for implicit authentication (e.g., auth/jwt/)",
			},
		},
		Operations: map[logical.Operation]OperationHandler{
			logical.ReadOperation: &PathOperation{
				Callback: b.handleConfigRead,
				Summary:  "Read access backend configuration",
			},
			logical.UpdateOperation: &PathOperation{
				Callback: b.handleConfigWrite,
				Summary:  "Configure access backend",
			},
		},
		HelpSynopsis:    "Configure access backend",
		HelpDescription: "Configure authentication settings.",
	}
}

func (b *AccessBackend) handleConfigRead(_ context.Context, _ *logical.Request, _ *FieldData) (*logical.Response, error) {
	cfg := b.GetAccessConfig()
	return &logical.Response{
		StatusCode: 200,
		Data: map[string]any{
			"auto_auth_path": cfg.AutoAuthPath,
		},
	}, nil
}

func (b *AccessBackend) handleConfigWrite(ctx context.Context, _ *logical.Request, d *FieldData) (*logical.Response, error) {
	cfg := b.GetAccessConfig()

	if v, ok := d.GetOk("auto_auth_path"); ok {
		cfg.AutoAuthPath = v.(string)
	}

	if err := b.SetAccessConfig(ctx, cfg); err != nil {
		return nil, err
	}

	return &logical.Response{StatusCode: 204}, nil
}
