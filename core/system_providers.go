package core

import (
	"context"
	"fmt"
	"maps"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logger"
)

// MountProvider creates a new provider mount
func (h *SystemHandlers) MountProvider(
	ctx context.Context,
	input *MountProviderInput,
) (*MountProviderOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("operation unauthorized",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Custom validation
	if err := ValidateMountPath(input.Path); err != nil {
		h.logger.Warn("mount path validation failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error400BadRequest(err.Error())
	}

	h.logger.Info("mounting provider",
		logger.String("path", input.Path),
		logger.String("type", input.Body.Type))

	// Create mount entry
	entry := &MountEntry{
		Class:       mountClassProvider,
		Type:        input.Body.Type,
		Path:        input.Path,
		Description: input.Body.Description,
		Config:      input.Body.Config,
	}

	// Mount via Core (handles validation, locking, router updates)
	if err := h.core.mount(ctx, entry); err != nil {
		h.logger.Error("mount failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, h.convertError(err)
	}

	// Return success
	output := &MountProviderOutput{}
	output.Body.Accessor = entry.Accessor
	output.Body.Path = entry.Path
	output.Body.Message = fmt.Sprintf("Successfully mounted %s provider at %s", input.Body.Type, input.Path)

	return output, nil
}

// UnmountProvider removes a provider mount
func (h *SystemHandlers) UnmountProvider(
	ctx context.Context,
	input *UnmountProviderInput,
) (*UnmountProviderOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("unmount operation unauthorized",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.logger.Info("unmounting provider", logger.String("path", input.Path))

	// Unmount via Core
	if err := h.core.unmount(ctx, input.Path); err != nil {
		h.logger.Error("unmount failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, h.convertError(err)
	}

	output := &UnmountProviderOutput{}
	output.Body.Message = fmt.Sprintf("Successfully unmounted %s", input.Path)
	return output, nil
}

// GetMountInfo retrieves mount information
func (h *SystemHandlers) GetMountInfo(
	ctx context.Context,
	input *GetMountInput,
) (*GetMountOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("get mount info operation unauthorized",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.core.mountsLock.RLock()
	defer h.core.mountsLock.RUnlock()

	// Normalize path
	path := input.Path
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	entry, err := h.core.mounts.findByPath(ctx, path)
	if err != nil {
		return nil, h.convertError(err)
	}
	if entry == nil {
		return nil, huma.Error404NotFound("Mount not found")
	}

	output := &GetMountOutput{}
	output.Body.Type = entry.Type
	output.Body.Path = entry.Path
	output.Body.Description = entry.Description
	output.Body.Accessor = entry.Accessor

	// Deep copy config and redact sensitive fields
	entry.configMu.RLock()
	config := make(map[string]any)
	maps.Copy(config, entry.Config)
	entry.configMu.RUnlock()

	// Redact sensitive keys
	if _, exists := config["hmac_key"]; exists && config["hmac_key"] != "" {
		config["hmac_key"] = "*************"
	}
	output.Body.Config = config

	return output, nil
}

// ListMounts retrieves all mounts
func (h *SystemHandlers) ListMounts(
	ctx context.Context,
	input *ListMountsInput,
) (*ListMountsOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("list mounts operation unauthorized",
			logger.Err(err))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.core.mountsLock.RLock()
	defer h.core.mountsLock.RUnlock()

	mounts := make(map[string]MountInfo)

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	for _, entry := range h.core.mounts.Entries {
		// Only returns entry of class provider in the specified namespace
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

		mounts[entry.Path] = MountInfo{
			Type:        entry.Type,
			Description: entry.Description,
			Accessor:    entry.Accessor,
			Config:      config,
		}
	}

	output := &ListMountsOutput{}
	output.Body.Mounts = mounts
	return output, nil
}

// ConfigureProvider configures an existing provider mount
func (h *SystemHandlers) ConfigureProvider(
	ctx context.Context,
	input *TuneProviderInput,
) (*TuneProviderOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("tune mount operation unauthorized",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Tune via Core
	if err := h.core.configureMount(ctx, input.Path, input.Body, true); err != nil {
		h.logger.Error("failed to configure mount",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, h.convertError(err)
	}

	output := &TuneProviderOutput{}
	output.Body.Message = fmt.Sprintf("Successfully tuned mount at %s", input.Path)
	return output, nil
}

// convertError converts internal errors to HUMA errors with generic messages
func (h *SystemHandlers) convertError(err error) error {
	errMsg := err.Error()

	// Log the detailed error internally
	h.logger.Error("operation error", logger.Err(err))

	// Return error messages - validation errors should be descriptive, others generic for security
	switch {
	case strings.Contains(errMsg, "invalid configuration"),
		strings.Contains(errMsg, "failed to setup backend with new config"):
		return huma.Error400BadRequest(errMsg)
	case strings.Contains(errMsg, "already in use"),
		strings.Contains(errMsg, "already exists"):
		return huma.Error409Conflict(errMsg)
	case strings.Contains(errMsg, "no matching mount"):
		return huma.Error404NotFound(errMsg)
	case strings.Contains(errMsg, "cannot mount"), strings.Contains(errMsg, "cannot tune"):
		return huma.Error403Forbidden("Operation not permitted")
	case strings.Contains(errMsg, "not supported"):
		return huma.Error400BadRequest("Invalid mount type")
	case strings.Contains(errMsg, "can't insert namespace with missing parent"):
		return huma.Error400BadRequest("can't create namespace with missing parent")
	case strings.Contains(errMsg, "cannot delete namespace"):
		return huma.Error400BadRequest(errMsg)
	default:
		// Return the actual error message for better debugging
		// TODO: In production, consider returning a generic message for security
		return huma.Error500InternalServerError(errMsg)
	}
}
