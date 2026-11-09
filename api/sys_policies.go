package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Policy type identifiers accepted by the typed policy methods. They are the
// path segment under sys/policies/.
const (
	PolicyTypeCBP = "cbp"
	PolicyTypeMCP = "mcp"
)

// PolicyOutput represents policy information
type PolicyOutput struct {
	Name   string `json:"name"`
	Policy string `json:"policy"`
}

// PutPolicy creates or updates a capability-based policy
func (c *Sys) PutPolicy(name string, policy string) error {
	return c.PutPolicyWithContext(context.Background(), name, policy)
}

// PutPolicyWithContext creates or updates a capability-based policy with context
func (c *Sys) PutPolicyWithContext(ctx context.Context, name string, policy string) error {
	return c.PutPolicyOfTypeWithContext(ctx, PolicyTypeCBP, name, policy)
}

// PutPolicyOfType creates or updates a policy of the given type
func (c *Sys) PutPolicyOfType(policyType, name, policy string) error {
	return c.PutPolicyOfTypeWithContext(context.Background(), policyType, name, policy)
}

// PutPolicyOfTypeWithContext creates or updates a policy of the given type with context
func (c *Sys) PutPolicyOfTypeWithContext(ctx context.Context, policyType, name, policy string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/policies/%s/%s", policyType, name))

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

// GetPolicy retrieves a capability-based policy
func (c *Sys) GetPolicy(name string) (*PolicyOutput, error) {
	return c.GetPolicyWithContext(context.Background(), name)
}

// GetPolicyWithContext retrieves a capability-based policy with context
func (c *Sys) GetPolicyWithContext(ctx context.Context, name string) (*PolicyOutput, error) {
	return c.GetPolicyOfTypeWithContext(ctx, PolicyTypeCBP, name)
}

// GetPolicyOfType retrieves a policy of the given type
func (c *Sys) GetPolicyOfType(policyType, name string) (*PolicyOutput, error) {
	return c.GetPolicyOfTypeWithContext(context.Background(), policyType, name)
}

// GetPolicyOfTypeWithContext retrieves a policy of the given type with context
func (c *Sys) GetPolicyOfTypeWithContext(ctx context.Context, policyType, name string) (*PolicyOutput, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/policies/%s/%s", policyType, name))

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

// ListPolicies lists all capability-based policies
func (c *Sys) ListPolicies() ([]string, error) {
	return c.ListPoliciesWithContext(context.Background())
}

// ListPoliciesWithContext lists capability-based policies with context
func (c *Sys) ListPoliciesWithContext(ctx context.Context) ([]string, error) {
	return c.ListPoliciesOfTypeWithContext(ctx, PolicyTypeCBP)
}

// ListPoliciesOfType lists all policies of the given type
func (c *Sys) ListPoliciesOfType(policyType string) ([]string, error) {
	return c.ListPoliciesOfTypeWithContext(context.Background(), policyType)
}

// ListPoliciesOfTypeWithContext lists policies of the given type with context
func (c *Sys) ListPoliciesOfTypeWithContext(ctx context.Context, policyType string) ([]string, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/policies/%s", policyType))
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

// DeletePolicy deletes a capability-based policy
func (c *Sys) DeletePolicy(name string) error {
	return c.DeletePolicyWithContext(context.Background(), name)
}

// DeletePolicyWithContext deletes a capability-based policy with context
func (c *Sys) DeletePolicyWithContext(ctx context.Context, name string) error {
	return c.DeletePolicyOfTypeWithContext(ctx, PolicyTypeCBP, name)
}

// DeletePolicyOfType deletes a policy of the given type
func (c *Sys) DeletePolicyOfType(policyType, name string) error {
	return c.DeletePolicyOfTypeWithContext(context.Background(), policyType, name)
}

// DeletePolicyOfTypeWithContext deletes a policy of the given type with context
func (c *Sys) DeletePolicyOfTypeWithContext(ctx context.Context, policyType, name string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/policies/%s/%s", policyType, name))

	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
