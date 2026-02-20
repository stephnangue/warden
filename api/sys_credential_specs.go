package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// CreateCredentialSpecInput represents the input for creating a credential spec
type CreateCredentialSpecInput struct {
	Type           string            `json:"type"`
	Source         string            `json:"source"`
	Config         map[string]string `json:"config,omitempty"`
	MinTTL         time.Duration     `json:"min_ttl"`
	MaxTTL         time.Duration     `json:"max_ttl"`
	RotationPeriod time.Duration     `json:"rotation_period,omitempty"` // 0 means no rotation
}

// CreateCredentialSpecOutput represents the output after creating a credential spec
type CreateCredentialSpecOutput struct {
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Source         string            `json:"source"`
	Config         map[string]string `json:"config,omitempty"`
	MinTTL         time.Duration     `json:"min_ttl"`
	MaxTTL         time.Duration     `json:"max_ttl"`
	RotationPeriod time.Duration     `json:"rotation_period,omitempty"`
	Message        string            `json:"message"`
}

// CredentialSpecInfo represents credential spec metadata
type CredentialSpecInfo struct {
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Source         string            `json:"source"`
	Config         map[string]string `json:"config,omitempty"`
	MinTTL         time.Duration     `json:"min_ttl"`
	MaxTTL         time.Duration     `json:"max_ttl"`
	RotationPeriod time.Duration     `json:"rotation_period,omitempty"`
}

// UpdateCredentialSpecInput represents the input for updating a credential spec
type UpdateCredentialSpecInput struct {
	Config         map[string]string `json:"config,omitempty"`
	MinTTL         *time.Duration    `json:"min_ttl,omitempty"`
	MaxTTL         *time.Duration    `json:"max_ttl,omitempty"`
	RotationPeriod *time.Duration    `json:"rotation_period,omitempty"` // nil means no change, 0 disables rotation
}

// UpdateCredentialSpecOutput represents the output after updating a credential spec
type UpdateCredentialSpecOutput struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// CreateCredentialSpec creates a new credential spec
func (c *Sys) CreateCredentialSpec(name string, input *CreateCredentialSpecInput) (*CreateCredentialSpecOutput, error) {
	return c.CreateCredentialSpecWithContext(context.Background(), name, input)
}

// CreateCredentialSpecWithContext creates a new credential spec with context
func (c *Sys) CreateCredentialSpecWithContext(ctx context.Context, name string, input *CreateCredentialSpecInput) (*CreateCredentialSpecOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/cred/specs/%s", name))

	if input == nil {
		return nil, errors.New("input cannot be nil")
	}

	// Convert to API request format (durations to seconds)
	reqBody := map[string]interface{}{
		"type":    input.Type,
		"source":  input.Source,
		"min_ttl": int64(input.MinTTL.Seconds()),
		"max_ttl": int64(input.MaxTTL.Seconds()),
	}
	if input.Config != nil {
		reqBody["config"] = input.Config
	}
	if input.RotationPeriod > 0 {
		reqBody["rotation_period"] = int64(input.RotationPeriod.Seconds())
	}

	if err := r.SetJSONBody(reqBody); err != nil {
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

	output := &CreateCredentialSpecOutput{}
	if n, ok := resource.Data["name"].(string); ok {
		output.Name = n
	}
	if t, ok := resource.Data["type"].(string); ok {
		output.Type = t
	}
	if src, ok := resource.Data["source"].(string); ok {
		output.Source = src
	}
	if msg, ok := resource.Data["message"].(string); ok {
		output.Message = msg
	}
	if cfg := parseConfigMap(resource.Data["config"]); cfg != nil {
		output.Config = cfg
	}
	if v, ok := resource.Data["min_ttl"]; ok {
		output.MinTTL = parseDurationFromSeconds(v)
	}
	if v, ok := resource.Data["max_ttl"]; ok {
		output.MaxTTL = parseDurationFromSeconds(v)
	}
	if v, ok := resource.Data["rotation_period"]; ok {
		output.RotationPeriod = parseDurationFromSeconds(v)
	}

	return output, nil
}

// GetCredentialSpec retrieves information about a specific credential spec
func (c *Sys) GetCredentialSpec(name string) (*CredentialSpecInfo, error) {
	return c.GetCredentialSpecWithContext(context.Background(), name)
}

// GetCredentialSpecWithContext retrieves credential spec information with context
func (c *Sys) GetCredentialSpecWithContext(ctx context.Context, name string) (*CredentialSpecInfo, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/cred/specs/%s", name))

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

	spec := &CredentialSpecInfo{}
	if n, ok := resource.Data["name"].(string); ok {
		spec.Name = n
	}
	if t, ok := resource.Data["type"].(string); ok {
		spec.Type = t
	}
	if src, ok := resource.Data["source"].(string); ok {
		spec.Source = src
	}
	if cfg := parseConfigMap(resource.Data["config"]); cfg != nil {
		spec.Config = cfg
	}
	if v, ok := resource.Data["min_ttl"]; ok {
		spec.MinTTL = parseDurationFromSeconds(v)
	}
	if v, ok := resource.Data["max_ttl"]; ok {
		spec.MaxTTL = parseDurationFromSeconds(v)
	}
	if v, ok := resource.Data["rotation_period"]; ok {
		spec.RotationPeriod = parseDurationFromSeconds(v)
	}

	return spec, nil
}

// ListCredentialSpecs lists all credential specs
func (c *Sys) ListCredentialSpecs() ([]*CredentialSpecInfo, error) {
	return c.ListCredentialSpecsWithContext(context.Background())
}

// ListCredentialSpecsWithContext lists credential specs with context
func (c *Sys) ListCredentialSpecsWithContext(ctx context.Context) ([]*CredentialSpecInfo, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/cred/specs")

	r.Params.Set("warden-list", "true")

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

	specsData, ok := resource.Data["specs"].([]interface{})
	if !ok {
		return []*CredentialSpecInfo{}, nil
	}

	specs := make([]*CredentialSpecInfo, 0, len(specsData))
	for _, item := range specsData {
		specMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		spec := &CredentialSpecInfo{}
		if n, ok := specMap["name"].(string); ok {
			spec.Name = n
		}
		if t, ok := specMap["type"].(string); ok {
			spec.Type = t
		}
		if src, ok := specMap["source"].(string); ok {
			spec.Source = src
		}
		if cfg := parseConfigMap(specMap["config"]); cfg != nil {
			spec.Config = cfg
		}
		if v, ok := specMap["min_ttl"]; ok {
			spec.MinTTL = parseDurationFromSeconds(v)
		}
		if v, ok := specMap["max_ttl"]; ok {
			spec.MaxTTL = parseDurationFromSeconds(v)
		}
		if v, ok := specMap["rotation_period"]; ok {
			spec.RotationPeriod = parseDurationFromSeconds(v)
		}

		specs = append(specs, spec)
	}

	return specs, nil
}

// UpdateCredentialSpec updates a credential spec
func (c *Sys) UpdateCredentialSpec(name string, input *UpdateCredentialSpecInput) (*UpdateCredentialSpecOutput, error) {
	return c.UpdateCredentialSpecWithContext(context.Background(), name, input)
}

// UpdateCredentialSpecWithContext updates a credential spec with context
func (c *Sys) UpdateCredentialSpecWithContext(ctx context.Context, name string, input *UpdateCredentialSpecInput) (*UpdateCredentialSpecOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/cred/specs/%s", name))

	if input == nil {
		input = &UpdateCredentialSpecInput{}
	}

	// Convert to API request format (durations to seconds)
	reqBody := make(map[string]interface{})
	if input.Config != nil {
		reqBody["config"] = input.Config
	}
	if input.MinTTL != nil {
		reqBody["min_ttl"] = int64(input.MinTTL.Seconds())
	}
	if input.MaxTTL != nil {
		reqBody["max_ttl"] = int64(input.MaxTTL.Seconds())
	}
	if input.RotationPeriod != nil {
		reqBody["rotation_period"] = int64(input.RotationPeriod.Seconds())
	}

	if err := r.SetJSONBody(reqBody); err != nil {
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

	output := &UpdateCredentialSpecOutput{}
	if n, ok := resource.Data["name"].(string); ok {
		output.Name = n
	}
	if msg, ok := resource.Data["message"].(string); ok {
		output.Message = msg
	}

	return output, nil
}

// DeleteCredentialSpec deletes a credential spec
func (c *Sys) DeleteCredentialSpec(name string) error {
	return c.DeleteCredentialSpecWithContext(context.Background(), name)
}

// DeleteCredentialSpecWithContext deletes a credential spec with context
func (c *Sys) DeleteCredentialSpecWithContext(ctx context.Context, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/cred/specs/%s", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
