package core

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathProviders returns the paths for provider operations
func (b *SystemBackend) pathProviders() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "providers/" + framework.MatchAllRegex("path"),
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "The path to mount the provider",
					Required:    true,
				},
				"type": {
					Type:        framework.TypeString,
					Description: "Provider type (e.g., aws, gcp)",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Human-readable description",
				},
				"config": {
					Type:        framework.TypeMap,
					Description: "Provider-specific configuration",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleProviderCreate,
					Summary:  "Enable a provider at the specified path",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleProviderRead,
					Summary:  "Get provider information",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleProviderDelete,
					Summary:  "Disable a provider",
				},
			},
			HelpSynopsis:    "Manage provider mounts",
			HelpDescription: "Enable, disable, and get information about provider mounts.",
		},
		{
			Pattern: "providers/?$",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleProviderList,
					Summary:  "List all providers",
				},
			},
			HelpSynopsis:    "List providers",
			HelpDescription: "List all enabled providers in the current namespace.",
		},
	}
}

// handleProviderCreate handles POST /sys/providers/{path}
func (b *SystemBackend) handleProviderCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)
	providerType := d.Get("type").(string)
	description, _ := d.Get("description").(string)
	config, _ := d.Get("config").(map[string]any)

	// Custom validation
	if err := ValidateMountPath(path); err != nil {
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
	}

	// Create mount entry
	entry := &MountEntry{
		Class:       mountClassProvider,
		Type:        providerType,
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
		"message":  fmt.Sprintf("Successfully mounted %s provider at %s", providerType, path),
	}), nil
}

// handleProviderRead handles GET /sys/providers/{path}
func (b *SystemBackend) handleProviderRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
		return logical.ErrorResponse(logical.ErrNotFound("mount not found")), nil
	}

	// Deep copy config and redact sensitive fields
	entry.configMu.RLock()
	config := make(map[string]any)
	maps.Copy(config, entry.Config)
	entry.configMu.RUnlock()

	// Redact sensitive keys
	if _, exists := config["hmac_key"]; exists && config["hmac_key"] != "" {
		config["hmac_key"] = "*************"
	}

	return b.respondSuccess(map[string]any{
		"type":        entry.Type,
		"path":        entry.Path,
		"description": entry.Description,
		"accessor":    entry.Accessor,
		"config":      config,
	}), nil
}

// handleProviderDelete handles DELETE /sys/providers/{path}
func (b *SystemBackend) handleProviderDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	// Unmount via Core
	if err := b.core.unmount(ctx, path); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"message": fmt.Sprintf("Successfully unmounted %s", path),
	}), nil
}

// handleProviderList handles GET /sys/providers
func (b *SystemBackend) handleProviderList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.core.mountsLock.RLock()
	defer b.core.mountsLock.RUnlock()

	mounts := make(map[string]any)

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	for _, entry := range b.core.mounts.Entries {
		// Only return entries of class provider in the specified namespace
		if entry.Class != mountClassProvider || entry.NamespaceID != ns.ID {
			continue
		}

		// Deep copy config and redact sensitive fields
		entry.configMu.RLock()
		config := make(map[string]any)
		maps.Copy(config, entry.Config)
		entry.configMu.RUnlock()

		// Redact sensitive keys
		if _, exists := config["hmac_key"]; exists && config["hmac_key"] != "" {
			config["hmac_key"] = "*************"
		}

		mounts[entry.Path] = map[string]any{
			"type":        entry.Type,
			"description": entry.Description,
			"accessor":    entry.Accessor,
			"config":      config,
		}
	}

	return b.respondSuccess(map[string]any{
		"mounts": mounts,
	}), nil
}

