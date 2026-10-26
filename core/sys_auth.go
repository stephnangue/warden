package core

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"

	authhelper "github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
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
				"force": {
					Type: framework.TypeBool,
					Description: "On disable (DELETE sys/auth/<path>?force=true): disable even while native " +
						"identities are claimed on the mount; their claims are left on a mount that no longer " +
						"exists, listed by LIST sys/identity/entity?orphaned=true",
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

	// Validate mount path (same validation as providers)
	if err := ValidateMountPath(path); err != nil {
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
	}
	// Configuration keys of the role era load ignored (with a warning) from
	// an existing mount, but a new mount is refused them.
	if err := authhelper.RefuseRemovedConfigKeys(config); err != nil {
		return logical.ErrorResponse(err), nil
	}

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

	b.core.authLock.RLock()
	defer b.core.authLock.RUnlock()

	// Normalize path
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	entry, err := b.core.auth.findByPath(ctx, path)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	if entry == nil {
		return logical.ErrorResponse(logical.ErrNotFound("auth method mount not found")), nil
	}

	// Defense-in-depth: c.auth is class-pure post-split, but verify so a
	// stray entry (test fixture bug, etc.) doesn't leak as an auth method.
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

	data := map[string]any{
		"type":        entry.Type,
		"path":        entry.Path,
		"description": entry.Description,
		"accessor":    entry.Accessor,
		"config":      maskedConfig,
	}
	if n := b.core.authRoleLeftoverCount(entry.UUID); n > 0 {
		appendWarnings(data, authRoleLeftoverWarning(entry.Path, n))
	}
	return b.respondSuccess(data), nil
}

// handleAuthDelete handles DELETE /sys/auth/{path}
func (b *SystemBackend) handleAuthDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	forced, err := b.core.refuseAuthMountDisable(ctx, path, d.Get("force").(bool))
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	b.logger.Info("unmounting auth method", logger.String("path", path))

	// Counted before the unmount, from the identity snapshot it does not touch.
	listed := b.core.groupsListingAuthMount(ctx, path)

	// Unmount via Core
	if err := b.core.unmount(ctx, path); err != nil {
		return logical.ErrorResponse(err), nil
	}

	data := map[string]any{
		"message": fmt.Sprintf("Successfully unmounted %s", path),
	}
	if listed > 0 {
		appendWarnings(data, mountDisableGroupsWarning(path, listed))
	}
	if forced != "" {
		appendWarnings(data, forced)
	}
	return b.respondSuccess(data), nil
}

// groupsListingAuthMount returns how many groups of ctx's namespace have a
// rule whose mount selector names the auth mount at path (relative to the
// namespace and to auth/, as sys/auth takes it), exactly or by a pattern.
func (c *Core) groupsListingAuthMount(ctx context.Context, path string) int {
	ns, err := namespace.FromContext(ctx)
	if err != nil || ns == nil {
		return 0
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return len(c.grantIndex(ns.ID).candidates(authRoutePrefix + path))
}

// mountDisableGroupsWarning is the warning for disabling the auth mount at
// path while n groups have a rule naming it. It names neither the groups nor
// their selectors.
func mountDisableGroupsWarning(path string, n int) string {
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return fmt.Sprintf("%d group(s) have a rule whose mount selector names %s%s; those rules match nothing "+
		"until a mount is enabled there again", n, authRoutePrefix, path)
}

// handleAuthList handles GET /sys/auth
func (b *SystemBackend) handleAuthList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.core.authLock.RLock()
	defer b.core.authLock.RUnlock()

	// c.auth is class-pure (only auth-class entries), so the namespace-only
	// accessor is sufficient — no class filter needed.
	entries, err := b.core.auth.findAllNamespaceMounts(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	mounts := make(map[string]any, len(entries))
	var warnings []string
	for _, entry := range entries {
		if n := b.core.authRoleLeftoverCount(entry.UUID); n > 0 {
			warnings = append(warnings, authRoleLeftoverWarning(entry.Path, n))
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

	data := map[string]any{
		"mounts": mounts,
	}
	// Sorted, so the listing reads the same whatever order the table holds.
	sort.Strings(warnings)
	appendWarnings(data, warnings...)
	return b.respondSuccess(data), nil
}
