package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Group is a namespace group as the server returns it. Selectors are the
// group's rules as written; MaxAge is a duration string ("10m0s"), empty when
// unset. Hash is what a conditional update or delete passes back as
// GroupInput.ExpectedHash; Warnings carries non-fatal notices about a write (a
// role that does not exist yet, a fact no listed auth mount produces).
type Group struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Type        string                `json:"type"`
	Description string                `json:"description"`
	Roles       []string              `json:"roles"`
	Selectors   []map[string][]string `json:"selectors"`
	MaxAge      string                `json:"max_age"`
	Metadata    map[string]string     `json:"metadata"`
	Hash        string                `json:"hash,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
	UpdatedAt   time.Time             `json:"updated_at"`
	Warnings    []string              `json:"warnings,omitempty"`
}

// GroupInput is the body of a group create or update. On update a nil field
// keeps the stored value and a non-nil one replaces it, even when empty (an
// empty Roles clears the roles). Type is required on create ("virtual") and
// may be left empty on update.
type GroupInput struct {
	Type        string
	Description *string
	Roles       []string
	Selectors   []map[string][]string
	MaxAge      *string
	Metadata    map[string]string

	// ExpectedHash, on update, applies the write only if the group still has
	// this hash (Group.Hash from an earlier read).
	ExpectedHash string
}

func (in *GroupInput) body() map[string]any {
	out := map[string]any{}
	if in == nil {
		return out
	}
	if in.Type != "" {
		out["type"] = in.Type
	}
	if in.Description != nil {
		out["description"] = *in.Description
	}
	if in.Roles != nil {
		out["roles"] = in.Roles
	}
	if in.Selectors != nil {
		out["selectors"] = in.Selectors
	}
	if in.MaxAge != nil {
		out["max_age"] = *in.MaxAge
	}
	if in.Metadata != nil {
		out["metadata"] = in.Metadata
	}
	if in.ExpectedHash != "" {
		out["expected_hash"] = in.ExpectedHash
	}
	return out
}

func decodeGroup(v any) (*Group, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var g Group
	if err := json.Unmarshal(raw, &g); err != nil {
		return nil, fmt.Errorf("failed to decode group: %w", err)
	}
	return &g, nil
}

func (c *Sys) groupRequest(ctx context.Context, r *Request) (*Group, error) {
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
	return decodeGroup(resource.Data)
}

// CreateGroup creates the group name in the client's namespace.
func (c *Sys) CreateGroup(name string, input *GroupInput) (*Group, error) {
	return c.CreateGroupWithContext(context.Background(), name, input)
}

// CreateGroupWithContext creates the group name with context.
func (c *Sys) CreateGroupWithContext(ctx context.Context, name string, input *GroupInput) (*Group, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/identity/group/%s", name))
	if err := r.SetJSONBody(input.body()); err != nil {
		return nil, err
	}
	return c.groupRequest(ctx, r)
}

// ReadGroup reads the group name.
func (c *Sys) ReadGroup(name string) (*Group, error) {
	return c.ReadGroupWithContext(context.Background(), name)
}

// ReadGroupWithContext reads the group name with context.
func (c *Sys) ReadGroupWithContext(ctx context.Context, name string) (*Group, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/identity/group/%s", name))
	return c.groupRequest(ctx, r)
}

// UpdateGroup updates the group name with the fields input sets.
func (c *Sys) UpdateGroup(name string, input *GroupInput) (*Group, error) {
	return c.UpdateGroupWithContext(context.Background(), name, input)
}

// UpdateGroupWithContext updates the group name with context.
func (c *Sys) UpdateGroupWithContext(ctx context.Context, name string, input *GroupInput) (*Group, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/identity/group/%s", name))
	if err := r.SetJSONBody(input.body()); err != nil {
		return nil, err
	}
	return c.groupRequest(ctx, r)
}

// DeleteGroup deletes the group name. A non-empty expectedHash deletes it only
// if it still has that hash.
func (c *Sys) DeleteGroup(name, expectedHash string) error {
	return c.DeleteGroupWithContext(context.Background(), name, expectedHash)
}

// DeleteGroupWithContext deletes the group name with context.
func (c *Sys) DeleteGroupWithContext(ctx context.Context, name, expectedHash string) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/identity/group/%s", name))
	if expectedHash != "" {
		r.Params.Set("expected_hash", expectedHash)
	}
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// ListGroups lists the groups of the client's namespace, sorted by name. A
// non-empty role lists only the groups that grant it.
func (c *Sys) ListGroups(role string) ([]*Group, error) {
	return c.ListGroupsWithContext(context.Background(), role)
}

// ListGroupsWithContext lists the groups with context.
func (c *Sys) ListGroupsWithContext(ctx context.Context, role string) ([]*Group, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/identity/group")
	r.Params.Set("warden-list", "true")
	if role != "" {
		r.Params.Set("role", role)
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
		return []*Group{}, nil
	}
	items, _ := resource.Data["groups"].([]any)
	groups := make([]*Group, 0, len(items))
	for _, item := range items {
		g, err := decodeGroup(item)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, nil
}
