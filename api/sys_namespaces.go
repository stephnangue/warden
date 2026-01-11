package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// CreateNamespaceInput represents the input for creating a namespace
type CreateNamespaceInput struct {
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

// CreateNamespaceOutput represents the output after creating a namespace
type CreateNamespaceOutput struct {
	ID             string            `json:"id"`
	Path           string            `json:"path"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
	Message        string            `json:"message"`
}

// GetNamespaceOutput represents namespace information
type GetNamespaceOutput struct {
	ID             string            `json:"id"`
	Path           string            `json:"path"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
	Tainted        bool              `json:"tainted"`
	Uuid           string            `json:"uuid"`
	Locked         bool              `json:"locked"`
}

// NamespaceInfo represents namespace metadata
type NamespaceInfo struct {
	Path           string            `json:"path"`
	ID             string            `json:"id"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

// UpdateNamespaceInput represents the input for updating a namespace
type UpdateNamespaceInput struct {
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
}

// UpdateNamespaceOutput represents the output after updating a namespace
type UpdateNamespaceOutput struct {
	ID             string            `json:"id"`
	Path           string            `json:"path"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
	Message        string            `json:"message"`
}

// CreateNamespace creates a new namespace at the specified path
func (c *Sys) CreateNamespace(path string, input *CreateNamespaceInput) (*CreateNamespaceOutput, error) {
	return c.CreateNamespaceWithContext(context.Background(), path, input)
}

// CreateNamespaceWithContext creates a new namespace with context
func (c *Sys) CreateNamespaceWithContext(ctx context.Context, path string, input *CreateNamespaceInput) (*CreateNamespaceOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/namespaces/%s", path))

	if input == nil {
		input = &CreateNamespaceInput{}
	}

	if err := r.SetJSONBody(input); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resource, err := ParseResource(resp.Body)
	if err != nil {
		return nil, err
	}
	if resource == nil || resource.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	output := &CreateNamespaceOutput{}
	if id, ok := resource.Data["id"].(string); ok {
		output.ID = id
	}
	if p, ok := resource.Data["path"].(string); ok {
		output.Path = p
	}
	if msg, ok := resource.Data["message"].(string); ok {
		output.Message = msg
	}
	if metadata, ok := resource.Data["custom_metadata"].(map[string]interface{}); ok {
		output.CustomMetadata = make(map[string]string)
		for k, v := range metadata {
			if str, ok := v.(string); ok {
				output.CustomMetadata[k] = str
			}
		}
	}

	return output, nil
}

// GetNamespace retrieves information about a specific namespace
func (c *Sys) GetNamespace(path string) (*GetNamespaceOutput, error) {
	return c.GetNamespaceWithContext(context.Background(), path)
}

// GetNamespaceWithContext retrieves namespace information with context
func (c *Sys) GetNamespaceWithContext(ctx context.Context, path string) (*GetNamespaceOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/namespaces/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resource, err := ParseResource(resp.Body)
	if err != nil {
		return nil, err
	}
	if resource == nil || resource.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	output := &GetNamespaceOutput{}
	if id, ok := resource.Data["id"].(string); ok {
		output.ID = id
	}
	if p, ok := resource.Data["path"].(string); ok {
		output.Path = p
	}
	if l, ok := resource.Data["lcoked"].(bool); ok {
		output.Locked = l
	}
	if t, ok := resource.Data["tainted"].(bool); ok {
		output.Tainted = t
	}
	if uuid, ok := resource.Data["uuid"].(string); ok {
		output.Uuid = uuid
	}
	if metadata, ok := resource.Data["custom_metadata"].(map[string]interface{}); ok {
		output.CustomMetadata = make(map[string]string)
		for k, v := range metadata {
			if str, ok := v.(string); ok {
				output.CustomMetadata[k] = str
			}
		}
	}

	return output, nil
}

// ListNamespaces lists all namespaces
func (c *Sys) ListNamespaces(recursive bool, includeParent bool) ([]*NamespaceInfo, error) {
	return c.ListNamespacesWithContext(context.Background(), recursive, includeParent)
}

// ListNamespacesWithContext lists namespaces with context
func (c *Sys) ListNamespacesWithContext(ctx context.Context, recursive bool, includeParent bool) ([]*NamespaceInfo, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/namespaces")

	r.Params.Set("list", "true")
	if recursive {
		r.Params.Set("recursive", "true")
	}
	if includeParent {
		r.Params.Set("include_parent", "true")
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resource, err := ParseResource(resp.Body)
	if err != nil {
		return nil, err
	}
	if resource == nil || resource.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	namespacesData, ok := resource.Data["namespaces"].([]interface{})
	if !ok {
		return []*NamespaceInfo{}, nil
	}

	namespaces := make([]*NamespaceInfo, 0, len(namespacesData))
	for _, item := range namespacesData {
		nsMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		ns := &NamespaceInfo{}
		if id, ok := nsMap["id"].(string); ok {
			ns.ID = id
		}
		if path, ok := nsMap["path"].(string); ok {
			ns.Path = path
		}
		if metadata, ok := nsMap["custom_metadata"].(map[string]interface{}); ok {
			ns.CustomMetadata = make(map[string]string)
			for k, v := range metadata {
				if str, ok := v.(string); ok {
					ns.CustomMetadata[k] = str
				}
			}
		}

		namespaces = append(namespaces, ns)
	}

	return namespaces, nil
}

// UpdateNamespace updates a namespace's metadata
func (c *Sys) UpdateNamespace(path string, input *UpdateNamespaceInput) (*UpdateNamespaceOutput, error) {
	return c.UpdateNamespaceWithContext(context.Background(), path, input)
}

// UpdateNamespaceWithContext updates a namespace with context
func (c *Sys) UpdateNamespaceWithContext(ctx context.Context, path string, input *UpdateNamespaceInput) (*UpdateNamespaceOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/namespaces/%s", path))

	if input == nil {
		input = &UpdateNamespaceInput{}
	}

	if err := r.SetJSONBody(input); err != nil {
		return nil, err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resource, err := ParseResource(resp.Body)
	if err != nil {
		return nil, err
	}
	if resource == nil || resource.Data == nil {
		return nil, errors.New("data from server response is empty")
	}

	output := &UpdateNamespaceOutput{}
	if id, ok := resource.Data["id"].(string); ok {
		output.ID = id
	}
	if p, ok := resource.Data["path"].(string); ok {
		output.Path = p
	}
	if msg, ok := resource.Data["message"].(string); ok {
		output.Message = msg
	}
	if metadata, ok := resource.Data["custom_metadata"].(map[string]interface{}); ok {
		output.CustomMetadata = make(map[string]string)
		for k, v := range metadata {
			if str, ok := v.(string); ok {
				output.CustomMetadata[k] = str
			}
		}
	}

	return output, nil
}

// DeleteNamespace deletes a namespace
func (c *Sys) DeleteNamespace(path string) error {
	return c.DeleteNamespaceWithContext(context.Background(), path)
}

// DeleteNamespaceWithContext deletes a namespace with context
func (c *Sys) DeleteNamespaceWithContext(ctx context.Context, path string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/namespaces/%s", path))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
