package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Role is a namespace role as the server returns it. Hash is what a
// conditional update or delete passes back as RoleInput.ExpectedHash; Warnings
// carries non-fatal notices about a write (a policy or credential spec that
// does not exist yet).
type Role struct {
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Policies     []string          `json:"policies"`
	CredSpecName string            `json:"cred_spec_name"`
	Skill        string            `json:"skill"`
	ProviderPath string            `json:"provider_path"`
	Metadata     map[string]string `json:"metadata"`
	Hash         string            `json:"hash,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	Warnings     []string          `json:"warnings,omitempty"`
}

// RoleInput is the body of a role create or update. On update a nil field
// keeps the stored value and a non-nil one replaces it, even when empty (an
// empty Policies clears the policies). On create a nil field is empty.
type RoleInput struct {
	Description  *string
	Policies     []string
	CredSpecName *string
	Skill        *string
	ProviderPath *string
	Metadata     map[string]string

	// ExpectedHash, on update, applies the write only if the role still has
	// this hash (Role.Hash from an earlier read).
	ExpectedHash string
}

// body renders in as the request body, sending only the fields it sets.
func (in *RoleInput) body() map[string]any {
	out := map[string]any{}
	if in == nil {
		return out
	}
	if in.Description != nil {
		out["description"] = *in.Description
	}
	if in.Policies != nil {
		out["policies"] = in.Policies
	}
	if in.CredSpecName != nil {
		out["cred_spec_name"] = *in.CredSpecName
	}
	if in.Skill != nil {
		out["skill"] = *in.Skill
	}
	if in.ProviderPath != nil {
		out["provider_path"] = *in.ProviderPath
	}
	if in.Metadata != nil {
		out["metadata"] = in.Metadata
	}
	if in.ExpectedHash != "" {
		out["expected_hash"] = in.ExpectedHash
	}
	return out
}

// decodeRole converts one role object of a response into a Role.
func decodeRole(v any) (*Role, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var r Role
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("failed to decode role: %w", err)
	}
	return &r, nil
}

// roleRequest sends r and decodes the role in the response data.
func (c *Sys) roleRequest(ctx context.Context, r *Request) (*Role, error) {
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
	return decodeRole(resource.Data)
}

// CreateRole creates the role name in the client's namespace.
func (c *Sys) CreateRole(name string, input *RoleInput) (*Role, error) {
	return c.CreateRoleWithContext(context.Background(), name, input)
}

// CreateRoleWithContext creates the role name with context.
func (c *Sys) CreateRoleWithContext(ctx context.Context, name string, input *RoleInput) (*Role, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/roles/%s", name))
	if err := r.SetJSONBody(input.body()); err != nil {
		return nil, err
	}
	return c.roleRequest(ctx, r)
}

// ReadRole reads the role name.
func (c *Sys) ReadRole(name string) (*Role, error) {
	return c.ReadRoleWithContext(context.Background(), name)
}

// ReadRoleWithContext reads the role name with context.
func (c *Sys) ReadRoleWithContext(ctx context.Context, name string) (*Role, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/roles/%s", name))
	return c.roleRequest(ctx, r)
}

// UpdateRole updates the role name with the fields input sets.
func (c *Sys) UpdateRole(name string, input *RoleInput) (*Role, error) {
	return c.UpdateRoleWithContext(context.Background(), name, input)
}

// UpdateRoleWithContext updates the role name with context.
func (c *Sys) UpdateRoleWithContext(ctx context.Context, name string, input *RoleInput) (*Role, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/roles/%s", name))
	if err := r.SetJSONBody(input.body()); err != nil {
		return nil, err
	}
	return c.roleRequest(ctx, r)
}

// DeleteRole deletes the role name. A non-empty expectedHash deletes it only if
// it still has that hash. The warnings name the groups that still list the
// role, which grant nothing through it until it is created again.
func (c *Sys) DeleteRole(name, expectedHash string) ([]string, error) {
	return c.DeleteRoleWithContext(context.Background(), name, expectedHash)
}

// DeleteRoleWithContext deletes the role name with context.
func (c *Sys) DeleteRoleWithContext(ctx context.Context, name, expectedHash string) ([]string, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/roles/%s", name))
	if expectedHash != "" {
		r.Params.Set("expected_hash", expectedHash)
	}
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	resource, err := ParseResource(resp.Body)
	if err != nil || resource == nil || resource.Data == nil {
		// The role is deleted; a body that does not parse only loses warnings.
		return nil, nil
	}
	raw, _ := resource.Data["warnings"].([]any)
	warnings := make([]string, 0, len(raw))
	for _, w := range raw {
		if s, ok := w.(string); ok && s != "" {
			warnings = append(warnings, s)
		}
	}
	return warnings, nil
}

// ListRoles lists the roles of the client's namespace, sorted by name. A
// non-empty providerPath lists only the roles used with that provider mount.
func (c *Sys) ListRoles(providerPath string) ([]*Role, error) {
	return c.ListRolesWithContext(context.Background(), providerPath)
}

// ListRolesWithContext lists the roles with context.
func (c *Sys) ListRolesWithContext(ctx context.Context, providerPath string) ([]*Role, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/roles")
	r.Params.Set("warden-list", "true")
	if providerPath != "" {
		r.Params.Set("provider_path", providerPath)
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
		return []*Role{}, nil
	}
	items, _ := resource.Data["roles"].([]any)
	roles := make([]*Role, 0, len(items))
	for _, item := range items {
		role, err := decodeRole(item)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, nil
}
