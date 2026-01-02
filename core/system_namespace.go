package core

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/logger"
)

// CreateNamespace creates a new namespace
func (h *SystemHandlers) CreateNamespace(
	ctx context.Context,
	input *CreateNamespaceInput,
) (*CreateNamespaceOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("create namespace operation unauthorized",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.logger.Info("creating namespace",
		logger.String("path", input.Path))

	// Create namespace via namespace store
	entry, err := h.core.namespaceStore.ModifyNamespaceByPath(ctx, input.Path, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		ns.CustomMetadata = input.Body.CustomMetadata
		return ns, nil
	})

	if err != nil {
		h.logger.Error("create namespace failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, h.convertError(err)
	}

	// Return success
	output := &CreateNamespaceOutput{}
	output.Body.ID = entry.ID
	output.Body.Path = entry.Path
	output.Body.CustomMetadata = entry.CustomMetadata
	output.Body.Message = fmt.Sprintf("Successfully created namespace at %s", input.Path)

	return output, nil
}

// GetNamespace retrieves namespace information
func (h *SystemHandlers) GetNamespace(
	ctx context.Context,
	input *GetNamespaceInput,
) (*GetNamespaceOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("get namespace operation unauthorized",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// Get namespace by path
	ns, err := h.core.namespaceStore.GetNamespaceByPath(ctx, input.Path)
	if err != nil {
		h.logger.Error("get namespace failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, h.convertError(err)
	}

	if ns == nil {
		return nil, huma.Error404NotFound("Namespace not found")
	}

	output := &GetNamespaceOutput{}
	output.Body.ID = ns.ID
	output.Body.Path = ns.Path
	output.Body.CustomMetadata = ns.CustomMetadata
	output.Body.Tainted = ns.Tainted
	output.Body.Locked = ns.Locked
	output.Body.Uuid = ns.UUID

	return output, nil
}

// ListNamespaces retrieves all namespaces
func (h *SystemHandlers) ListNamespaces(
	ctx context.Context,
	input *ListNamespacesInput,
) (*ListNamespacesOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("list namespaces operation unauthorized",
			logger.Err(err))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	// List namespaces based on query parameters
	var namespaces []*namespace.Namespace
	var err error

	if input.Recursive {
		// List all descendant namespaces recursively
		namespaces, err = h.core.namespaceStore.ListNamespaces(ctx, input.IncludeParent, true)
	} else {
		// List only direct children
		namespaces, err = h.core.namespaceStore.ListNamespaces(ctx, input.IncludeParent, false)
	}

	if err != nil {
		h.logger.Error("list namespaces failed",
			logger.Err(err))
		return nil, h.convertError(err)
	}

	// Convert to response format
	namespaceInfos := make([]NamespaceInfo, 0, len(namespaces))
	for _, ns := range namespaces {
		namespaceInfos = append(namespaceInfos, NamespaceInfo{
			Path:           ns.Path,
			ID:             ns.ID,
			CustomMetadata: ns.CustomMetadata,
		})
	}

	output := &ListNamespacesOutput{}
	output.Body.Namespaces = namespaceInfos
	return output, nil
}

// UpdateNamespace updates an existing namespace
func (h *SystemHandlers) UpdateNamespace(
	ctx context.Context,
	input *UpdateNamespaceInput,
) (*UpdateNamespaceOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("update namespace operation unauthorized",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.logger.Info("updating namespace",
		logger.String("path", input.Path))

	// Update namespace via ModifyNamespaceByPath
	updatedNs, err := h.core.namespaceStore.ModifyNamespaceByPath(ctx, input.Path, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		// Update custom metadata
		if input.Body.CustomMetadata != nil {
			ns.CustomMetadata = input.Body.CustomMetadata
		}
		return ns, nil
	})

	if err != nil {
		h.logger.Error("update namespace failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, h.convertError(err)
	}

	output := &UpdateNamespaceOutput{}
	output.Body.ID = updatedNs.ID
	output.Body.Path = updatedNs.Path
	output.Body.CustomMetadata = updatedNs.CustomMetadata
	output.Body.Message = fmt.Sprintf("Successfully updated namespace at %s", input.Path)

	return output, nil
}

// DeleteNamespace deletes a namespace
func (h *SystemHandlers) DeleteNamespace(
	ctx context.Context,
	input *DeleteNamespaceInput,
) (*DeleteNamespaceOutput, error) {

	// Authorization check
	if err := h.checkSystemAdmin(ctx); err != nil {
		h.logger.Warn("delete namespace operation unauthorized",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, huma.Error403Forbidden("Insufficient permissions: system_admin role required")
	}

	h.logger.Info("deleting namespace",
		logger.String("path", input.Path))

	// Delete namespace via namespace store
	status, err := h.core.namespaceStore.DeleteNamespace(ctx, input.Path)
	if err != nil {
		h.logger.Error("delete namespace failed",
			logger.Err(err),
			logger.String("path", input.Path))
		return nil, h.convertError(err)
	}

	output := &DeleteNamespaceOutput{}
	if status == "in-progress" {
		output.Body.Message = fmt.Sprintf("Namespace deletion in progress for %s", input.Path)
	} else {
		output.Body.Message = fmt.Sprintf("Successfully deleted namespace at %s", input.Path)
	}

	return output, nil
}
