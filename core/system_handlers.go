package core

import (
	"context"
	"fmt"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stephnangue/warden/logger"
)

// SystemHandlers handles system backend operations
type SystemHandlers struct {
	core   *Core
	logger logger.Logger
}

// checkSystemAdmin verifies the authenticated principal has system_admin role
func (h *SystemHandlers) checkSystemAdmin(ctx context.Context) error {
	principalID, ok := ctx.Value(SystemPrincipalIDKey).(string)
	if !ok || principalID == "" {
		return fmt.Errorf("principal not found in context")
	}

	if !h.core.accessControl.IsAllowed(principalID, "system_admin") {
		h.logger.Warn("authorization failed: insufficient permissions",
			logger.String("principal_id", principalID),
			logger.String("required_role", "system_admin"))
		return fmt.Errorf("insufficient permissions: system_admin role required")
	}

	return nil
}

// MountProvider creates a new provider mount
func (h *SystemHandlers) MountProvider(
	ctx context.Context,
	input *MountProviderInput,
) (*MountProviderOutput, error) {
	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("mount operation unauthorized",
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
		logger.String("type", input.Type))

	// Create mount entry
	entry := &MountEntry{
		Class:       mountClassProvider,
		Type:        input.Type,
		Path:        input.Path,
		Description: input.Description,
		Config:      input.Config,
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
	output.Body.Message = fmt.Sprintf("Successfully mounted %s provider at %s", input.Type, input.Path)

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
	output.Body.Class = entry.Class
	output.Body.Type = entry.Type
	output.Body.Path = entry.Path
	output.Body.Description = entry.Description
	output.Body.Accessor = entry.Accessor
	output.Body.Tainted = entry.Tainted
	output.Body.Config = entry.Config

	return output, nil
}

// ListMounts retrieves all mounts
func (h *SystemHandlers) ListMounts(
	ctx context.Context,
	input *ListMountsInput,
) (*ListMountsOutput, error) {
	h.core.mountsLock.RLock()
	defer h.core.mountsLock.RUnlock()

	mounts := make(map[string]MountInfo)

	for _, entry := range h.core.mounts.Entries {
		// Filter by class if specified
		if input.Class != "" && entry.Class != input.Class {
			continue
		}

		mounts[entry.Path] = MountInfo{
			Class:       entry.Class,
			Type:        entry.Type,
			Description: entry.Description,
			Accessor:    entry.Accessor,
			Config:      entry.Config,
		}
	}

	output := &ListMountsOutput{}
	output.Body.Mounts = mounts
	return output, nil
}

// convertError converts internal errors to HUMA errors with generic messages
func (h *SystemHandlers) convertError(err error) error {
	errMsg := err.Error()

	// Log the detailed error internally
	h.logger.Error("operation error", logger.Err(err))

	// Return generic, security-conscious error messages
	switch {
	case strings.Contains(errMsg, "already in use"):
		return huma.Error409Conflict("Mount path conflict")
	case strings.Contains(errMsg, "no matching mount"):
		return huma.Error404NotFound("Mount not found")
	case strings.Contains(errMsg, "cannot mount"):
		return huma.Error403Forbidden("Operation not permitted")
	case strings.Contains(errMsg, "not supported"):
		return huma.Error400BadRequest("Invalid mount type")
	default:
		return huma.Error500InternalServerError("Internal server error")
	}
}
