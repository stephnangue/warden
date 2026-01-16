package core

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/logger"
)

// maskMountConfigValue is the default mask used for sensitive mount config fields
const maskMountConfigValue = "*************"

// maskMountConfig masks sensitive fields in mount configuration based on the backend's
// SensitiveFieldsProvider implementation
func (b *SystemBackend) maskMountConfig(ctx context.Context, entry *MountEntry, config map[string]any) map[string]any {
	if config == nil {
		return nil
	}

	// Get backend and check for SensitiveFieldsProvider
	var sensitiveFields []string
	if backend := b.core.router.MatchingBackend(ctx, entry.Path); backend != nil {
		if provider, ok := backend.(logical.SensitiveFieldsProvider); ok {
			sensitiveFields = provider.SensitiveConfigFields()
		}
	}

	// Build lookup for sensitive fields
	sensitive := make(map[string]bool)
	for _, f := range sensitiveFields {
		sensitive[f] = true
	}

	// Mask sensitive values
	masked := make(map[string]any, len(config))
	for k, v := range config {
		if sensitive[k] && v != nil && v != "" {
			masked[k] = maskMountConfigValue
		} else {
			masked[k] = v
		}
	}
	return masked
}

// pathAuth returns the paths for auth method operations
func (b *SystemBackend) pathAuth() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "auth/" + framework.MatchAllRegex("path"),
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "The path to mount the auth method",
					Required:    true,
				},
				"type": {
					Type:        framework.TypeString,
					Description: "Auth method type (e.g., jwt, oidc)",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Human-readable description",
				},
				"config": {
					Type:        framework.TypeMap,
					Description: "Auth method-specific configuration",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleAuthCreate,
					Summary:  "Enable an auth method at the specified path",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleAuthRead,
					Summary:  "Get auth method information",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleAuthDelete,
					Summary:  "Disable an auth method",
				},
			},
			HelpSynopsis:    "Manage auth method mounts",
			HelpDescription: "Enable, disable, and get information about auth method mounts.",
		},
		{
			Pattern: "auth/?$",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleAuthList,
					Summary:  "List all auth methods",
				},
			},
			HelpSynopsis:    "List auth methods",
			HelpDescription: "List all enabled auth methods in the current namespace.",
		},
	}
}

// handleAuthCreate handles POST /sys/auth/{path}
func (b *SystemBackend) handleAuthCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)
	authType := d.Get("type").(string)
	description, _ := d.Get("description").(string)
	config, _ := d.Get("config").(map[string]any)

	b.logger.Info("mounting auth method",
		logger.String("path", path),
		logger.String("type", authType))

	// Create mount entry
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        authType,
		Path:        path,
		Description: description,
		Config:      config,
	}

	// Mount via Core
	if err := b.core.mount(ctx, entry); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondCreated(map[string]any{
		"accessor": entry.Accessor,
		"path":     entry.Path,
		"message":  fmt.Sprintf("Successfully mounted %s auth method at %s", authType, path),
	}), nil
}

// handleAuthRead handles GET /sys/auth/{path}
func (b *SystemBackend) handleAuthRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	b.core.mountsLock.RLock()
	defer b.core.mountsLock.RUnlock()

	// Normalize path
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	entry, err := b.core.mounts.findByPath(ctx, path)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	if entry == nil {
		return logical.ErrorResponse(logical.ErrNotFound("auth method mount not found")), nil
	}

	// Verify it's an auth mount
	if entry.Class != mountClassAuth {
		return logical.ErrorResponse(logical.ErrNotFound("auth method mount not found")), nil
	}

	// Deep copy config
	entry.configMu.RLock()
	config := make(map[string]any)
	maps.Copy(config, entry.Config)
	entry.configMu.RUnlock()

	// Mask sensitive fields using schema-based approach
	maskedConfig := b.maskMountConfig(ctx, entry, config)

	return b.respondSuccess(map[string]any{
		"type":        entry.Type,
		"path":        entry.Path,
		"description": entry.Description,
		"accessor":    entry.Accessor,
		"config":      maskedConfig,
	}), nil
}

// handleAuthDelete handles DELETE /sys/auth/{path}
func (b *SystemBackend) handleAuthDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	b.logger.Info("unmounting auth method", logger.String("path", path))

	// Unmount via Core
	if err := b.core.unmount(ctx, path); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"message": fmt.Sprintf("Successfully unmounted %s", path),
	}), nil
}

// handleAuthList handles GET /sys/auth
func (b *SystemBackend) handleAuthList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.core.mountsLock.RLock()
	defer b.core.mountsLock.RUnlock()

	mounts := make(map[string]any)

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	for _, entry := range b.core.mounts.Entries {
		// Only return entries of class auth in the specified namespace
		if entry.Class != mountClassAuth || entry.NamespaceID != ns.ID {
			continue
		}

		// Deep copy config
		entry.configMu.RLock()
		config := make(map[string]any)
		maps.Copy(config, entry.Config)
		entry.configMu.RUnlock()

		// Mask sensitive fields using schema-based approach
		maskedConfig := b.maskMountConfig(ctx, entry, config)

		mounts[entry.Path] = map[string]any{
			"type":        entry.Type,
			"description": entry.Description,
			"accessor":    entry.Accessor,
			"config":      maskedConfig,
		}
	}

	return b.respondSuccess(map[string]any{
		"mounts": mounts,
	}), nil
}

