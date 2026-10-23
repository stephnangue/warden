package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Group is a namespace group as the server returns it. Rules are the group's
// rules as written, each a set of selectors (fact name to the values it may
// take); RuleCount and SelectorCount are what the group adds to the
// namespace's usage. ValidUntil is an RFC 3339 instant in UTC after which the
// group grants nothing, empty for no end.
// Hash is what a conditional update or delete passes back as
// GroupInput.ExpectedHash; Warnings carries non-fatal notices about a write (a
// role that does not exist yet, a fact no listed auth mount produces).
type Group struct {
	ID            string                `json:"id"`
	Name          string                `json:"name"`
	Type          string                `json:"type"`
	Description   string                `json:"description"`
	Roles         []string              `json:"roles"`
	Rules         []map[string][]string `json:"rules"`
	RuleCount     int                   `json:"rule_count"`
	SelectorCount int                   `json:"selector_count"`
	ValidUntil    string                `json:"valid_until"`
	Metadata      map[string]string     `json:"metadata"`
	Hash          string                `json:"hash,omitempty"`
	CreatedAt     time.Time             `json:"created_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
	Warnings      []string              `json:"warnings,omitempty"`
}

// IdentityUsage is a namespace's identity objects counted by kind, against
// their caps, as sys/identity/usage returns it. Groups is the only kind yet.
type IdentityUsage struct {
	Groups GroupsUsage `json:"groups"`
}

// GroupsUsage counts a namespace's groups: Total counts every group, Virtual
// the virtual ones with their caps.
type GroupsUsage struct {
	Total   int                `json:"total"`
	Virtual VirtualGroupsUsage `json:"virtual"`
}

// VirtualGroupsUsage counts virtual groups (Count, against Max) and the
// selectors of their rules, "mount" included (Selectors, against
// MaxSelectors).
type VirtualGroupsUsage struct {
	Count        int `json:"count"`
	Max          int `json:"max"`
	Selectors    int `json:"selectors"`
	MaxSelectors int `json:"max_selectors"`
}

// GroupInput is the body of a group create or update. On update a nil field
// keeps the stored value and a non-nil one replaces it, even when empty (an
// empty Roles clears the roles). Type is required on create ("virtual") and
// may be left empty on update.
type GroupInput struct {
	Type        string
	Description *string
	Roles       []string
	Rules       []map[string][]string
	ValidUntil  *string // RFC 3339; "" clears it on update
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
	if in.Rules != nil {
		out["rules"] = in.Rules
	}
	if in.ValidUntil != nil {
		out["valid_until"] = *in.ValidUntil
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
	groups := []*Group{}
	if resource == nil || resource.Data == nil {
		return groups, nil
	}
	items, _ := resource.Data["groups"].([]any)
	for _, item := range items {
		g, err := decodeGroup(item)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, nil
}

// ReadIdentityUsage reads the identity usage of the client's namespace.
func (c *Sys) ReadIdentityUsage() (*IdentityUsage, error) {
	return c.ReadIdentityUsageWithContext(context.Background())
}

// ReadIdentityUsageWithContext reads the identity usage with context.
func (c *Sys) ReadIdentityUsageWithContext(ctx context.Context) (*IdentityUsage, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/identity/usage")
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
	raw, err := json.Marshal(resource.Data)
	if err != nil {
		return nil, err
	}
	var u IdentityUsage
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, fmt.Errorf("failed to decode identity usage: %w", err)
	}
	return &u, nil
}
