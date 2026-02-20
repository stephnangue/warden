package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// PolicyOutput represents policy information
type PolicyOutput struct {
	Name   string `json:"name"`
	Policy string `json:"policy"`
}

// PutPolicy creates or updates a policy
func (c *Sys) PutPolicy(name string, policy string) error {
	return c.PutPolicyWithContext(context.Background(), name, policy)
}

// PutPolicyWithContext creates or updates a policy with context
func (c *Sys) PutPolicyWithContext(ctx context.Context, name string, policy string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/policies/cbp/%s", name))

	input := map[string]interface{}{
		"policy": policy,
	}

	if err := r.SetJSONBody(input); err != nil {
		return err
	}

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// GetPolicy retrieves a policy
func (c *Sys) GetPolicy(name string) (*PolicyOutput, error) {
	return c.GetPolicyWithContext(context.Background(), name)
}

// GetPolicyWithContext retrieves a policy with context
func (c *Sys) GetPolicyWithContext(ctx context.Context, name string) (*PolicyOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/policies/cbp/%s", name))

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

	output := &PolicyOutput{}
	if name, ok := resource.Data["name"].(string); ok {
		output.Name = name
	}
	if policy, ok := resource.Data["policy"].(string); ok {
		output.Policy = policy
	}

	return output, nil
}

// ListPolicies lists all policies
func (c *Sys) ListPolicies() ([]string, error) {
	return c.ListPoliciesWithContext(context.Background())
}

// ListPoliciesWithContext lists policies with context
func (c *Sys) ListPoliciesWithContext(ctx context.Context) ([]string, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/policies/cbp")
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

	keysData, ok := resource.Data["keys"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	keys := make([]string, 0, len(keysData))
	for _, item := range keysData {
		if key, ok := item.(string); ok {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// DeletePolicy deletes a policy
func (c *Sys) DeletePolicy(name string) error {
	return c.DeletePolicyWithContext(context.Background(), name)
}

// DeletePolicyWithContext deletes a policy with context
func (c *Sys) DeletePolicyWithContext(ctx context.Context, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/policies/cbp/%s", name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
