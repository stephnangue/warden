package core

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stephnangue/warden/logger"
)

// MountAuth creates a new auth method mount
func (h *SystemHandlers) MountAuth(
	ctx context.Context,
	input *MountAuthInput,
) (*MountAuthOutput, error) {
	// URL-decode the path (Chi doesn't decode path parameters automatically)
	decodedPath, err := url.PathUnescape(input.Path)
	if err != nil {
		h.logger.Warn("path decode failed",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, huma.Error400BadRequest(fmt.Sprintf("invalid path encoding: %v", err))
	}

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("operation unauthorized",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Custom validation
	if err := ValidateMountPath(decodedPath); err != nil {
		h.logger.Warn("mount path validation failed",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, huma.Error400BadRequest(err.Error())
	}

	h.logger.Info("mounting auth method",
		logger.String("path", decodedPath),
		logger.String("type", input.Body.Type))

	// Create mount entry
	entry := &MountEntry{
		Class:       mountClassAuth,
		Type:        input.Body.Type,
		Path:        decodedPath,
		Description: input.Body.Description,
		Config:      input.Body.Config,
	}

	// Mount via Core (handles validation, locking, router updates)
	if err := h.core.mount(ctx, entry); err != nil {
		h.logger.Error("mount failed",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, h.convertError(err)
	}

	// Return success
	output := &MountAuthOutput{}
	output.Body.Accessor = entry.Accessor
	output.Body.Path = entry.Path
	output.Body.Message = fmt.Sprintf("Successfully mounted %s auth method at %s", input.Body.Type, decodedPath)

	return output, nil
}

// UnmountAuth removes an auth method mount
func (h *SystemHandlers) UnmountAuth(
	ctx context.Context,
	input *UnmountAuthInput,
) (*UnmountAuthOutput, error) {
	// URL-decode the path
	decodedPath, err := url.PathUnescape(input.Path)
	if err != nil {
		h.logger.Warn("path decode failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error400BadRequest(fmt.Sprintf("invalid path encoding: %v", err))
	}

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("unmount operation unauthorized",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.logger.Info("unmounting auth method", logger.String("path", decodedPath))

	// Unmount via Core
	if err := h.core.unmount(ctx, decodedPath); err != nil {
		h.logger.Error("unmount failed",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, h.convertError(err)
	}

	output := &UnmountAuthOutput{}
	output.Body.Message = fmt.Sprintf("Successfully unmounted %s", decodedPath)
	return output, nil
}

// GetAuthInfo retrieves auth method mount information
func (h *SystemHandlers) GetAuthInfo(
	ctx context.Context,
	input *GetAuthInput,
) (*GetMountOutput, error) {
	// URL-decode the path
	decodedPath, err := url.PathUnescape(input.Path)
	if err != nil {
		h.logger.Warn("path decode failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error400BadRequest(fmt.Sprintf("invalid path encoding: %v", err))
	}

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("get auth info operation unauthorized",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.core.mountsLock.RLock()
	defer h.core.mountsLock.RUnlock()

	// Normalize path
	path := decodedPath
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	entry, err := h.core.mounts.findByPath(ctx, path)
	if err != nil {
		return nil, h.convertError(err)
	}
	if entry == nil {
		return nil, huma.Error404NotFound("Auth method mount not found")
	}

	// Verify it's an auth mount
	if entry.Class != mountClassAuth {
		return nil, huma.Error404NotFound("Auth method mount not found")
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

// ListAuths retrieves all auth method mounts
func (h *SystemHandlers) ListAuths(
	ctx context.Context,
	input *struct{},
) (*ListAuthsOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("list auth methods operation unauthorized",
			logger.Err(err))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.core.mountsLock.RLock()
	defer h.core.mountsLock.RUnlock()

	mounts := make(map[string]AuthInfo)

	for _, entry := range h.core.mounts.Entries {
		// Only return entries of class auth
		if entry.Class != mountClassAuth {
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

		mounts[entry.Path] = AuthInfo{
			Type:        entry.Type,
			Description: entry.Description,
			Accessor:    entry.Accessor,
			Config:      config,
		}
	}

	output := &ListAuthsOutput{}
	output.Body.Mounts = mounts
	return output, nil
}

// ConfigureAuth configure an existing auth method mount
func (h *SystemHandlers) ConfigureAuth(
	ctx context.Context,
	input *TuneAuthInput,
) (*TuneAuthOutput, error) {
	// URL-decode the path
	decodedPath, err := url.PathUnescape(input.Path)
	if err != nil {
		h.logger.Warn("path decode failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error400BadRequest(fmt.Sprintf("invalid path encoding: %v", err))
	}

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("tune auth method operation unauthorized",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.logger.Info("tuning auth method mount",
		logger.String("path", decodedPath))

	// Configure via Core
	if err := h.core.configureMount(ctx, decodedPath, input.Body); err != nil {
		h.logger.Error("tune auth method mount failed",
			logger.Err(err),
			logger.String("path", decodedPath))
		return nil, h.convertError(err)
	}

	output := &TuneAuthOutput{}
	output.Body.Message = fmt.Sprintf("Successfully tuned auth method mount at %s", decodedPath)
	return output, nil
}
