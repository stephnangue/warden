package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
	"github.com/stephnangue/warden/logger"
)

// generateHMACSalt generates a cryptographically secure random salt for HMAC operations.
// Returns a 32-byte hex-encoded string.
func generateHMACSalt() (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate HMAC salt: %w", err)
	}
	return hex.EncodeToString(salt), nil
}

// pathAudit returns the paths for audit device operations
func (b *SystemBackend) pathAudit() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "audit/" + framework.MatchAllRegex("path"),
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "The path of the audit device",
					Required:    true,
				},
				"type": {
					Type:        framework.TypeString,
					Description: "Audit device type (e.g., file)",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Human-readable description",
				},
				"config": {
					Type:        framework.TypeMap,
					Description: "Audit device-specific configuration",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleAuditCreate,
					Summary:  "Enable an audit device at the specified path",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleAuditCreate,
					Summary:  "Enable an audit device at the specified path",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleAuditRead,
					Summary:  "Get audit device information",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleAuditDelete,
					Summary:  "Disable an audit device",
				},
			},
			HelpSynopsis:    "Manage audit devices",
			HelpDescription: "Enable, disable, and get information about audit devices.",
		},
		{
			Pattern: "audit/?$",
			Fields: map[string]*framework.FieldSchema{
				"list": {
					Type:        framework.TypeBool,
					Description: "If true, list all audit devices",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleAuditList,
					Summary:  "List all audit devices",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleAuditListOrRead,
					Summary:  "List all audit devices (with list=true query param)",
				},
			},
			HelpSynopsis:    "List audit devices",
			HelpDescription: "List all enabled audit devices. Use list=true query parameter for GET requests.",
		},
	}
}

// pathAuditHash returns the path for the audit-hash endpoint
func (b *SystemBackend) pathAuditHash() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "audit-hash/" + framework.MatchAllRegex("path"),
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "The path of the audit device",
					Required:    true,
				},
				"input": {
					Type:        framework.TypeString,
					Description: "The input string to hash",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleAuditHash,
					Summary:  "Hash data using an audit device's HMAC salt",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleAuditHash,
					Summary:  "Hash data using an audit device's HMAC salt",
				},
			},
			HelpSynopsis:    "Hash data for audit log correlation",
			HelpDescription: "Hash the given input using the specified audit device's HMAC salt. This can be used to verify if a plaintext value appears in the audit logs.",
		},
	}
}

// handleAuditCreate handles PUT/POST /sys/audit/{path}
func (b *SystemBackend) handleAuditCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)
	auditType := d.Get("type").(string)
	description, _ := d.Get("description").(string)
	config, _ := d.Get("config").(map[string]any)

	if config == nil {
		config = make(map[string]any)
	}

	// Generate HMAC salt if not provided
	if config["hmac_key"] == nil || config["hmac_key"] == "" {
		salt, err := generateHMACSalt()
		if err != nil {
			return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
		}
		config["hmac_key"] = salt
	}

	b.logger.Info("enabling audit device",
		logger.String("path", path),
		logger.String("type", auditType))

	// Create mount entry for audit
	entry := &MountEntry{
		Class:       mountClassAudit,
		Type:        auditType,
		Path:        path,
		Description: description,
		Config:      config,
	}

	// Enable via Core (delegates to EnableAudit)
	if err := b.core.EnableAudit(ctx, entry, true); err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondCreated(map[string]any{
		"accessor": entry.Accessor,
		"path":     entry.Path,
		"message":  fmt.Sprintf("Successfully enabled %s audit device at %s", auditType, entry.Path),
	}), nil
}

// handleAuditRead handles GET /sys/audit/{path}
func (b *SystemBackend) handleAuditRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	b.core.auditLock.RLock()
	defer b.core.auditLock.RUnlock()

	// Normalize path
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Find in audit mount table
	var entry *MountEntry
	for _, e := range b.core.audit.Entries {
		if e.Path == path {
			entry = e
			break
		}
	}

	if entry == nil {
		return logical.ErrorResponse(logical.ErrNotFound("audit device not found")), nil
	}

	// Build response with masked config (hmac_key should be masked)
	config := make(map[string]any)
	for k, v := range entry.Config {
		if k == "hmac_key" && v != nil && v != "" {
			config[k] = maskMountConfigValue
		} else {
			config[k] = v
		}
	}

	return b.respondSuccess(map[string]any{
		"type":        entry.Type,
		"path":        entry.Path,
		"description": entry.Description,
		"accessor":    entry.Accessor,
		"config":      config,
	}), nil
}

// handleAuditDelete handles DELETE /sys/audit/{path}
func (b *SystemBackend) handleAuditDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	b.logger.Info("disabling audit device", logger.String("path", path))

	// CRITICAL SAFETY CHECK: Prevent disabling the last audit device
	// This enforces fail-closed audit compliance
	b.core.auditLock.RLock()
	deviceCount := len(b.core.audit.Entries)
	b.core.auditLock.RUnlock()

	if deviceCount <= 1 {
		return logical.ErrorResponse(logical.ErrBadRequest(
			"cannot disable the last audit device: Warden requires at least one audit device to operate (fail-closed mode)")), nil
	}

	// Disable via Core
	_, err := b.core.DisableAudit(ctx, path, true)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"message": fmt.Sprintf("Successfully disabled audit device at %s", path),
	}), nil
}

// handleAuditList handles GET /sys/audit
func (b *SystemBackend) handleAuditList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.core.auditLock.RLock()
	defer b.core.auditLock.RUnlock()

	audits := make(map[string]any)

	for _, entry := range b.core.audit.Entries {
		// Build config with masked sensitive fields
		config := make(map[string]any)
		for k, v := range entry.Config {
			if k == "hmac_key" && v != nil && v != "" {
				config[k] = maskMountConfigValue
			} else {
				config[k] = v
			}
		}

		audits[entry.Path] = map[string]any{
			"type":        entry.Type,
			"description": entry.Description,
			"accessor":    entry.Accessor,
			"config":      config,
		}
	}

	return b.respondSuccess(audits), nil
}

// handleAuditListOrRead handles GET /sys/audit with list=true query parameter
// This allows the API client to use a GET request with query params to list audit devices
func (b *SystemBackend) handleAuditListOrRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Check if list=true was provided - if so, delegate to list handler
	if listParam, ok := d.GetOk("list"); ok {
		if listBool, isBool := listParam.(bool); isBool && listBool {
			return b.handleAuditList(ctx, req, d)
		}
	}

	// If list parameter is not true, return an error since we need a path for read
	return logical.ErrorResponse(logical.ErrBadRequest("use list=true to list audit devices, or specify a path")), nil
}

// handleAuditHash handles POST /sys/audit-hash/{path}
func (b *SystemBackend) handleAuditHash(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)
	input := d.Get("input").(string)

	if input == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("input is required")), nil
	}

	b.core.auditLock.RLock()
	defer b.core.auditLock.RUnlock()

	// Normalize path
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// Find the audit device
	var entry *MountEntry
	for _, e := range b.core.audit.Entries {
		if e.Path == path {
			entry = e
			break
		}
	}

	if entry == nil {
		return logical.ErrorResponse(logical.ErrNotFound("audit device not found")), nil
	}

	// Get the HMAC key from config
	hmacKey, ok := entry.Config["hmac_key"].(string)
	if !ok || hmacKey == "" {
		return logical.ErrorResponse(logical.ErrInternal("audit device has no HMAC key configured")), nil
	}

	// Create HMACer and compute hash
	hmacer := audit.NewHMACer(hmacKey)
	hash, err := hmacer.Salt(ctx, input)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(fmt.Sprintf("failed to compute hash: %s", err))), nil
	}

	return b.respondSuccess(map[string]any{
		"hash": hash,
	}), nil
}
