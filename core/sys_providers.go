package core

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
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

	// Seed the agent-facing skill for this provider type, if one ships
	// with the package. First mount of a given type registers the skill;
	// later mounts of the same type are no-ops. Operator edits to a
	// previously seeded skill are preserved. Skill failures never block
	// the mount — the cluster is functional without the catalog entry.
	b.maybeSeedProviderSkill(ctx, providerType)

	return b.respondCreated(map[string]any{
		"accessor": entry.Accessor,
		"path":     entry.Path,
		"message":  fmt.Sprintf("Successfully mounted %s provider at %s", providerType, path),
	}), nil
}

// maybeSeedProviderSkill seeds the agent skill for providerType when both
// the wired-up markdown and the SkillStore are available. Errors are
// logged but do not propagate — see handleProviderCreate.
func (b *SystemBackend) maybeSeedProviderSkill(ctx context.Context, providerType string) {
	if b.core.skillStore == nil {
		return
	}
	md, ok := b.core.providerSkills[providerType]
	if !ok || md == "" {
		return
	}
	if err := b.core.skillStore.SeedProviderSkill(ctx, providerType, md); err != nil {
		b.logger.Warn("failed to seed provider skill",
			logger.String("type", providerType),
			logger.Err(err),
		)
	}
}

// mountURL builds the agent-facing relative URL path for a mount. The
// return value is what an agent appends to $WARDEN_ADDR to reach the
// mount's root; the agent then appends the per-provider suffix
// (e.g. "gateway", "role/<role>/gateway", "access/<grant>") taken from
// the matching skill.
//
// Examples:
//
//	root namespace, mount "aws/"        → "/v1/aws/"
//	namespace "team-data/", mount "aws/" → "/v1/team-data/aws/"
//
// The format mirrors how the request router resolves mounts internally
// (ns.Path + mount + req.Path in core/router.go), so the value is
// guaranteed to match the route an agent's HTTP call would hit.
func mountURL(ns *namespace.Namespace, mountPath string) string {
	if ns == nil {
		return "/v1/" + mountPath
	}
	return "/v1/" + ns.Path + mountPath
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
		"mount_url":   mountURL(entry.Namespace(), entry.Path),
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

		// Deep copy config
		entry.configMu.RLock()
		config := make(map[string]any)
		maps.Copy(config, entry.Config)
		entry.configMu.RUnlock()

		// Mask sensitive fields using schema-based approach
		maskedConfig := b.maskMountConfig(ctx, entry, config)

		mounts[entry.Path] = map[string]any{
			"type":        entry.Type,
			"path":        entry.Path,
			"description": entry.Description,
			"accessor":    entry.Accessor,
			"config":      maskedConfig,
			"mount_url":   mountURL(ns, entry.Path),
		}
	}

	return b.respondSuccess(map[string]any{
		"mounts": mounts,
	}), nil
}
