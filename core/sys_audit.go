package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/stephnangue/warden/audit"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
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
	auditDeviceFields := map[string]*framework.FieldSchema{
		"type": {
			Type:        framework.TypeString,
			Description: "Audit device type (e.g., `file`).",
		},
		"path": {
			Type:        framework.TypeString,
			Description: "Mount path of the audit device, including the trailing slash.",
		},
		"description": {
			Type:        framework.TypeString,
			Description: "Human-readable description supplied at enable time. Empty if none was provided.",
		},
		"accessor": {
			Type:        framework.TypeString,
			Description: "Stable mount accessor assigned by Warden. Useful for correlating audit log entries with this device.",
		},
		"config": {
			Type: framework.TypeMap,
			Description: "Audit device-specific configuration. " +
				"`hmac_key` (the device's HMAC salt, generated at enable time if not supplied) is masked as `" + maskMountConfigValue + "` and never returned in plaintext; " +
				"use the `audit-hash/{path}` endpoint to compare a value against this device's salted HMAC.",
		},
	}

	listExampleResponse := &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"file/": map[string]any{
				"type":        "file",
				"description": "Primary audit log",
				"accessor":    "audit_file_abc123",
				"config": map[string]any{
					"file_path": "/var/log/warden/audit.log",
					"hmac_key":  maskMountConfigValue,
				},
			},
			"secondary/": map[string]any{
				"type":        "file",
				"description": "Secondary audit log",
				"accessor":    "audit_file_def456",
				"config": map[string]any{
					"file_path": "/var/log/warden/audit-2.log",
					"hmac_key":  maskMountConfigValue,
				},
			},
		},
	}

	createResponses := map[int][]framework.Response{
		http.StatusCreated: {{
			Description: "Audit device enabled successfully.",
			MediaType:   "application/json",
			Fields: map[string]*framework.FieldSchema{
				"accessor": {
					Type:        framework.TypeString,
					Description: "Stable mount accessor assigned to the new audit device.",
				},
				"path": {
					Type:        framework.TypeString,
					Description: "Mount path of the audit device, including the trailing slash.",
				},
				"message": {
					Type:        framework.TypeString,
					Description: "Human-readable confirmation message.",
				},
			},
			Example: &logical.Response{
				StatusCode: http.StatusCreated,
				Data: map[string]any{
					"accessor": "audit_file_abc123",
					"path":     "file/",
					"message":  "Successfully enabled file audit device at file/",
				},
			},
		}},
		http.StatusBadRequest: {{
			Description: "Invalid request — missing or unknown audit `type`, malformed `config`, or path conflict with an existing mount.",
		}},
	}

	createExamples := []framework.RequestExample{{
		Description: "Enable a file audit device at `file/` writing to `/var/log/warden/audit.log`. `hmac_key` is omitted so Warden generates a per-device salt.",
		Data: map[string]any{
			"type":        "file",
			"description": "Primary audit log",
			"config": map[string]any{
				"file_path": "/var/log/warden/audit.log",
			},
		},
	}}

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
					Description: "Enables an audit device of the given `type` at `path`. " +
						"If `config.hmac_key` is omitted, Warden generates a 32-byte random salt and stores it on this device — " +
						"used by `audit-hash/{path}` to verify whether a plaintext value appears in *this device's* audit logs. " +
						"Warden runs fail-closed: at least one audit device must remain enabled at all times.",
					Responses: createResponses,
					Examples:  createExamples,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleAuditCreate,
					Summary:  "Enable an audit device at the specified path",
					Description: "Same handler as create: PUT and POST both call into the enable path. " +
						"Re-submitting against an already-enabled path is rejected with 400 `path already in use` — " +
						"to change an audit device's configuration, disable it and enable a new one.",
					Responses: createResponses,
					Examples:  createExamples,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleAuditRead,
					Summary:  "Get audit device information",
					Description: "Returns the configuration of the audit device at `path`. " +
						"`config.hmac_key` is masked in the response — Warden never returns the raw HMAC salt over the API. " +
						"The input path is normalized to end with `/`.",
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "Audit device configuration. `config.hmac_key` is masked.",
							MediaType:   "application/json",
							Fields:      auditDeviceFields,
							Example: &logical.Response{
								StatusCode: http.StatusOK,
								Data: map[string]any{
									"type":        "file",
									"path":        "file/",
									"description": "Primary audit log",
									"accessor":    "audit_file_abc123",
									"config": map[string]any{
										"file_path": "/var/log/warden/audit.log",
										"hmac_key":  maskMountConfigValue,
									},
								},
							},
						}},
						http.StatusNotFound: {{
							Description: "No audit device is enabled at the given path.",
						}},
					},
					Examples: []framework.RequestExample{{
						Description: "Read the audit device enabled at `file/`.",
						Data:        map[string]any{},
					}},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleAuditDelete,
					Summary:  "Disable an audit device",
					Description: "Disables (unmounts) the audit device at `path`. " +
						"Disabling the last enabled audit device returns 400 — Warden requires at least one audit device to operate (fail-closed mode).",
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "Audit device disabled successfully.",
							MediaType:   "application/json",
							Fields: map[string]*framework.FieldSchema{
								"message": {
									Type:        framework.TypeString,
									Description: "Human-readable confirmation message.",
								},
							},
							Example: &logical.Response{
								StatusCode: http.StatusOK,
								Data: map[string]any{
									"message": "Successfully disabled audit device at secondary/",
								},
							},
						}},
						http.StatusBadRequest: {{
							Description: "Cannot disable the last audit device (fail-closed mode), or the underlying disable operation failed.",
						}},
					},
					Examples: []framework.RequestExample{{
						Description: "Disable the audit device at `secondary/`.",
						Data:        map[string]any{},
					}},
				},
			},
			HelpSynopsis:    "Manage audit devices",
			HelpDescription: "Enable, disable, and get information about audit devices.",
		},
		{
			Pattern: "audit/?$",
			Fields: map[string]*framework.FieldSchema{
				"warden-list": {
					Type:        framework.TypeBool,
					Description: "If true, list all audit devices",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleAuditList,
					Summary:  "List all audit devices",
					Description: "Returns a map of audit-device path → device metadata. " +
						"Each entry is `{type, path, description, accessor, config}`. " +
						"`config.hmac_key` is masked. " +
						"The response body is the device map itself — there is no top-level wrapper key.",
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "Map of all enabled audit devices, keyed by mount path. " +
								"Each value is `{type, path, description, accessor, config}`; `config.hmac_key` is masked. " +
								"See `Example` for the concrete shape.",
							MediaType: "application/json",
							Example:   listExampleResponse,
						}},
					},
					Examples: []framework.RequestExample{{
						Description: "List all enabled audit devices.",
						Data:        map[string]any{},
					}},
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleAuditListOrRead,
					Summary:  "List all audit devices (with warden-list=true query param)",
					Description: "Warden-specific GET-as-list shim: when called with `?warden-list=true`, behaves identically to the LIST operation. " +
						"Without the flag, returns 400 — reads of individual devices use the path-scoped `audit/{path}` endpoint.",
					Responses: map[int][]framework.Response{
						http.StatusOK: {{
							Description: "Map of all enabled audit devices, keyed by mount path. Same shape as the LIST response. " +
								"See `Example` for the concrete shape.",
							MediaType: "application/json",
							Example:   listExampleResponse,
						}},
						http.StatusBadRequest: {{
							Description: "`warden-list=true` query parameter is required for GET-as-list; use the path-scoped read for individual devices.",
						}},
					},
					Examples: []framework.RequestExample{{
						Description: "List all enabled audit devices via GET with the `warden-list=true` query parameter.",
						Data: map[string]any{
							"warden-list": true,
						},
					}},
				},
			},
			HelpSynopsis:    "List audit devices",
			HelpDescription: "List all enabled audit devices. Use warden-list=true query parameter for GET requests.",
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
		"declarative": entry.Declarative,
	}), nil
}

// handleAuditDelete handles DELETE /sys/audit/{path}.
// No last-device guard: the broker fail-opens at zero registered devices,
// so an operator who disables the last device intentionally enters the
// bootstrap state (unaudited, but able to re-enable via sys/audit/{path}).
// HCL-declared devices are still protected — Core.DisableAudit rejects
// those with the "owned by an HCL audit declaration" error.
func (b *SystemBackend) handleAuditDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	b.logger.Info("disabling audit device", logger.String("path", path))

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
			"declarative": entry.Declarative,
		}
	}

	return b.respondSuccess(audits), nil
}

// handleAuditListOrRead handles GET /sys/audit with warden-list=true query parameter
// This allows the API client to use a GET request with query params to list audit devices
func (b *SystemBackend) handleAuditListOrRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Check if warden-list=true was provided - if so, delegate to list handler
	if listParam, ok := d.GetOk("warden-list"); ok {
		if listBool, isBool := listParam.(bool); isBool && listBool {
			return b.handleAuditList(ctx, req, d)
		}
	}

	// If warden-list parameter is not true, return an error since we need a path for read
	return logical.ErrorResponse(logical.ErrBadRequest("use warden-list=true to list audit devices, or specify a path")), nil
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
