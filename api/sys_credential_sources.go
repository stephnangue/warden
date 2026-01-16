package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// CreateCredentialSourceInput represents the input for creating a credential source
type CreateCredentialSourceInput struct {
	Type   string            `json:"type"`
	Config map[string]string `json:"config,omitempty"`
}

// CreateCredentialSourceOutput represents the output after creating a credential source
type CreateCredentialSourceOutput struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Config  map[string]string `json:"config,omitempty"`
	Message string            `json:"message"`
}

// CredentialSourceInfo represents credential source metadata
type CredentialSourceInfo struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Config map[string]string `json:"config,omitempty"`
}

// UpdateCredentialSourceInput represents the input for updating a credential source
type UpdateCredentialSourceInput struct {
	Config map[string]string `json:"config,omitempty"`
}

// UpdateCredentialSourceOutput represents the output after updating a credential source
type UpdateCredentialSourceOutput struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// CreateCredentialSource creates a new credential source
func (c *Sys) CreateCredentialSource(name string, input *CreateCredentialSourceInput) (*CreateCredentialSourceOutput, error) {
	return c.CreateCredentialSourceWithContext(context.Background(), name, input)
}

// CreateCredentialSourceWithContext creates a new credential source with context
func (c *Sys) CreateCredentialSourceWithContext(ctx context.Context, name string, input *CreateCredentialSourceInput) (*CreateCredentialSourceOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/cred/sources/%s", name))

	if input == nil {
		return nil, errors.New("input cannot be nil")
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

	output := &CreateCredentialSourceOutput{}
	if n, ok := resource.Data["name"].(string); ok {
		output.Name = n
	}
	if t, ok := resource.Data["type"].(string); ok {
		output.Type = t
	}
	if msg, ok := resource.Data["message"].(string); ok {
		output.Message = msg
	}
	if config, ok := resource.Data["config"].(map[string]any); ok {
		output.Config = make(map[string]string)
		for k, v := range config {
			output.Config[k] = configValueToString(v)
		}
	}

	return output, nil
}

// GetCredentialSource retrieves information about a specific credential source
func (c *Sys) GetCredentialSource(name string) (*CredentialSourceInfo, error) {
	return c.GetCredentialSourceWithContext(context.Background(), name)
}

// GetCredentialSourceWithContext retrieves credential source information with context
func (c *Sys) GetCredentialSourceWithContext(ctx context.Context, name string) (*CredentialSourceInfo, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/cred/sources/%s", name))

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

	source := &CredentialSourceInfo{}
	if n, ok := resource.Data["name"].(string); ok {
		source.Name = n
	}
	if t, ok := resource.Data["type"].(string); ok {
		source.Type = t
	}
	if config, ok := resource.Data["config"].(map[string]any); ok {
		source.Config = make(map[string]string)
		for k, v := range config {
			source.Config[k] = configValueToString(v)
		}
	}

	return source, nil
}

// ListCredentialSources lists all credential sources
func (c *Sys) ListCredentialSources() ([]*CredentialSourceInfo, error) {
	return c.ListCredentialSourcesWithContext(context.Background())
}

// ListCredentialSourcesWithContext lists credential sources with context
func (c *Sys) ListCredentialSourcesWithContext(ctx context.Context) ([]*CredentialSourceInfo, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/cred/sources")

	r.Params.Set("list", "true")

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

	sourcesData, ok := resource.Data["sources"].([]any)
	if !ok {
		return []*CredentialSourceInfo{}, nil
	}

	sources := make([]*CredentialSourceInfo, 0, len(sourcesData))
	for _, item := range sourcesData {
		sourceMap, ok := item.(map[string]any)
		if !ok {
			continue
		}

		source := &CredentialSourceInfo{}
		if n, ok := sourceMap["name"].(string); ok {
			source.Name = n
		}
		if t, ok := sourceMap["type"].(string); ok {
			source.Type = t
		}
		if config, ok := sourceMap["config"].(map[string]any); ok {
			source.Config = make(map[string]string)
			for k, v := range config {
				source.Config[k] = configValueToString(v)
			}
		}

		sources = append(sources, source)
	}

	return sources, nil
}

// UpdateCredentialSource updates a credential source
func (c *Sys) UpdateCredentialSource(name string, input *UpdateCredentialSourceInput) (*UpdateCredentialSourceOutput, error) {
	return c.UpdateCredentialSourceWithContext(context.Background(), name, input)
}

// UpdateCredentialSourceWithContext updates a credential source with context
func (c *Sys) UpdateCredentialSourceWithContext(ctx context.Context, name string, input *UpdateCredentialSourceInput) (*UpdateCredentialSourceOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/cred/sources/%s", name))

	if input == nil {
		input = &UpdateCredentialSourceInput{}
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

	output := &UpdateCredentialSourceOutput{}
	if n, ok := resource.Data["name"].(string); ok {
		output.Name = n
	}
	if msg, ok := resource.Data["message"].(string); ok {
		output.Message = msg
	}

	return output, nil
}

// DeleteCredentialSource deletes a credential source
func (c *Sys) DeleteCredentialSource(name string) error {
	return c.DeleteCredentialSourceWithContext(context.Background(), name)
}

// DeleteCredentialSourceWithContext deletes a credential source with context
func (c *Sys) DeleteCredentialSourceWithContext(ctx context.Context, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/cred/sources/%s", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// configValueToString converts various types from JSON to string representation
// This ensures all config values remain as strings even if the server returns typed values
func configValueToString(v any) string {
	if v == nil {
		return ""
	}

	switch val := v.(type) {
	case string:
		return val
	case json.Number:
		return val.String()
	case bool:
		return strconv.FormatBool(val)
	case float64:
		// Check if it's an integer value
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		return strconv.FormatFloat(val, 'f', -1, 64)
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", val)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val)
	default:
		// Fall back to fmt.Sprint for other types
		return fmt.Sprint(val)
	}
}
