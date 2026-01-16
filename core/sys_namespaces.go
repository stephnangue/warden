package core

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// convertMetadataToStringMap converts map[string]any to map[string]string for namespace metadata
func convertMetadataToStringMap(m map[string]any) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			result[k] = s
		} else {
			result[k] = fmt.Sprintf("%v", v)
		}
	}
	return result
}

// pathNamespaces returns the paths for namespace operations
func (b *SystemBackend) pathNamespaces() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "namespaces/" + framework.MatchAllRegex("path"),
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "The namespace path",
					Required:    true,
				},
				"custom_metadata": {
					Type:        framework.TypeMap,
					Description: "Custom metadata for the namespace",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleNamespaceCreate,
					Summary:  "Create a new namespace",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleNamespaceRead,
					Summary:  "Get namespace information",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleNamespaceUpdate,
					Summary:  "Update namespace",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleNamespaceDelete,
					Summary:  "Delete a namespace",
				},
			},
			HelpSynopsis:    "Manage namespaces",
			HelpDescription: "Create, read, update, and delete namespaces.",
		},
		{
			Pattern: "namespaces/?$",
			Fields: map[string]*framework.FieldSchema{
				"recursive": {
					Type:        framework.TypeBool,
					Description: "List namespaces recursively",
					Default:     false,
				},
				"include_parent": {
					Type:        framework.TypeBool,
					Description: "Include parent namespace in the list",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleNamespaceList,
					Summary:  "List all namespaces",
				},
			},
			HelpSynopsis:    "List namespaces",
			HelpDescription: "List all namespaces in the current namespace.",
		},
	}
}

// handleNamespaceCreate handles POST /sys/namespaces/{path}
func (b *SystemBackend) handleNamespaceCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)
	customMetadata, _ := d.Get("custom_metadata").(map[string]any)

	b.logger.Info("creating namespace", logger.String("path", path))

	// Create namespace via namespace store
	entry, err := b.core.namespaceStore.ModifyNamespaceByPath(ctx, path, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		ns.CustomMetadata = convertMetadataToStringMap(customMetadata)
		return ns, nil
	})

	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondCreated(map[string]any{
		"id":              entry.ID,
		"path":            entry.Path,
		"custom_metadata": entry.CustomMetadata,
		"message":         fmt.Sprintf("Successfully created namespace at %s", path),
	}), nil
}

// handleNamespaceRead handles GET /sys/namespaces/{path}
func (b *SystemBackend) handleNamespaceRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	// Get namespace by path
	ns, err := b.core.namespaceStore.GetNamespaceByPath(ctx, path)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	if ns == nil {
		return logical.ErrorResponse(logical.ErrNotFound("namespace not found")), nil
	}

	return b.respondSuccess(map[string]any{
		"id":              ns.ID,
		"path":            ns.Path,
		"custom_metadata": ns.CustomMetadata,
		"tainted":         ns.Tainted,
		"locked":          ns.Locked,
		"uuid":            ns.UUID,
	}), nil
}

// handleNamespaceUpdate handles PUT /sys/namespaces/{path}
func (b *SystemBackend) handleNamespaceUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)
	customMetadata, _ := d.Get("custom_metadata").(map[string]any)

	b.logger.Info("updating namespace", logger.String("path", path))

	// Update namespace via ModifyNamespaceByPath
	updatedNs, err := b.core.namespaceStore.ModifyNamespaceByPath(ctx, path, func(ctx context.Context, ns *namespace.Namespace) (*namespace.Namespace, error) {
		if customMetadata != nil {
			ns.CustomMetadata = convertMetadataToStringMap(customMetadata)
		}
		return ns, nil
	})

	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(map[string]any{
		"id":              updatedNs.ID,
		"path":            updatedNs.Path,
		"custom_metadata": updatedNs.CustomMetadata,
		"message":         fmt.Sprintf("Successfully updated namespace at %s", path),
	}), nil
}

// handleNamespaceDelete handles DELETE /sys/namespaces/{path}
func (b *SystemBackend) handleNamespaceDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	path := d.Get("path").(string)

	b.logger.Info("deleting namespace", logger.String("path", path))

	// Delete namespace via namespace store
	status, err := b.core.namespaceStore.DeleteNamespace(ctx, path)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	var message string
	if status == "in-progress" {
		message = fmt.Sprintf("Namespace deletion in progress for %s", path)
	} else {
		message = fmt.Sprintf("Successfully deleted namespace at %s", path)
	}

	return b.respondSuccess(map[string]any{
		"message": message,
	}), nil
}

// handleNamespaceList handles GET /sys/namespaces
func (b *SystemBackend) handleNamespaceList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	recursive, _ := d.Get("recursive").(bool)
	includeParent, _ := d.Get("include_parent").(bool)

	// List namespaces based on query parameters
	var namespaces []*namespace.Namespace
	var err error

	if recursive {
		namespaces, err = b.core.namespaceStore.ListNamespaces(ctx, includeParent, true)
	} else {
		namespaces, err = b.core.namespaceStore.ListNamespaces(ctx, includeParent, false)
	}

	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Convert to response format
	keys := make([]string, 0, len(namespaces))
	namespaceInfos := make([]map[string]any, 0, len(namespaces))
	for _, ns := range namespaces {
		keys = append(keys, ns.Path)
		namespaceInfos = append(namespaceInfos, map[string]any{
			"path":            ns.Path,
			"id":              ns.ID,
			"custom_metadata": ns.CustomMetadata,
		})
	}

	return b.respondSuccess(map[string]any{
		"keys":       keys,
		"namespaces": namespaceInfos,
	}), nil
}
