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
// their caps, as sys/identity/usage returns it.
type IdentityUsage struct {
	Groups     GroupsUsage     `json:"groups"`
	Identities IdentitiesUsage `json:"identities"`
}

// IdentitiesUsage counts a namespace's entities (Entities, against
// MaxEntities) and the native identities they claim (Aliases).
type IdentitiesUsage struct {
	Entities    int `json:"entities"`
	MaxEntities int `json:"max_entities"`
	Aliases     int `json:"aliases"`
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
// empty Roles clears the roles). Type is required on create and on update, and
// on update must be the stored type.
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

// ReadGroup reads the group name. A non-empty groupType must be the stored
// type; a policy that conditions the group paths on the type needs it.
func (c *Sys) ReadGroup(name, groupType string) (*Group, error) {
	return c.ReadGroupWithContext(context.Background(), name, groupType)
}

// ReadGroupWithContext reads the group name with context.
func (c *Sys) ReadGroupWithContext(ctx context.Context, name, groupType string) (*Group, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/identity/group/%s", name))
	if groupType != "" {
		r.Params.Set("type", groupType)
	}
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

// DeleteGroup deletes the group name, which must be of type groupType (the
// server requires it), and returns the server's warnings (nil when there are
// none). A non-empty expectedHash deletes it only if it still has that hash.
// A group that sponsors entities, or is a pending handover for some, is
// deleted only with force: the handovers are cancelled and the entities lose
// their sponsor, which a warning says.
func (c *Sys) DeleteGroup(name, groupType, expectedHash string, force bool) ([]string, error) {
	return c.DeleteGroupWithContext(context.Background(), name, groupType, expectedHash, force)
}

// DeleteGroupWithContext deletes the group name with context.
func (c *Sys) DeleteGroupWithContext(ctx context.Context, name, groupType, expectedHash string, force bool) ([]string, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/identity/group/%s", name))
	r.Params.Set("type", groupType)
	if expectedHash != "" {
		r.Params.Set("expected_hash", expectedHash)
	}
	if force {
		r.Params.Set("force", "true")
	}
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	resource, perr := ParseResource(resp.Body)
	if perr != nil || resource == nil || resource.Data == nil {
		// The group is deleted; a body that does not parse only loses warnings.
		return nil, nil
	}
	return parseWarnings(resource.Data["warnings"]), nil
}

// ListGroups lists the groups of the client's namespace, sorted by name. A
// non-empty role lists only the groups that grant it, a non-empty groupType
// only the groups of that type.
func (c *Sys) ListGroups(role, groupType string) ([]*Group, error) {
	return c.ListGroupsWithContext(context.Background(), role, groupType)
}

// ListGroupsWithContext lists the groups with context.
func (c *Sys) ListGroupsWithContext(ctx context.Context, role, groupType string) ([]*Group, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/identity/group")
	r.Params.Set("warden-list", "true")
	if role != "" {
		r.Params.Set("role", role)
	}
	if groupType != "" {
		r.Params.Set("type", groupType)
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

// Entity is a namespace entity as the server returns it: an agent of record,
// the team accountable for it (Sponsor) and a proposed handover to another
// (PendingSponsor), its lifecycle State (active, suspended or retired) and the
// native identities it claims (Aliases). GovernedBy is derived by the server:
// "warden" once the entity has an accepted sponsor and a description, ""
// before, with UngovernedReason saying what is missing. Hash is what a
// conditional write passes back as its expected hash.
type Entity struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Kind             string            `json:"kind"`
	Description      string            `json:"description"`
	Sponsor          *EntitySponsor    `json:"sponsor"`
	PendingSponsor   *EntitySponsor    `json:"pending_sponsor"`
	State            string            `json:"state"`
	GovernedBy       string            `json:"governed_by"`
	UngovernedReason string            `json:"ungoverned_reason"`
	Profile          map[string]string `json:"profile"`
	Metadata         map[string]string `json:"metadata"`
	Aliases          []EntityAlias     `json:"aliases"`
	Hash             string            `json:"hash,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`

	// Warnings carries the server's notices about a write: a handover left
	// pending, a group nobody can act for, an entity left ungoverned.
	Warnings []string `json:"warnings,omitempty"`
}

// EntitySponsor is a team accountable for an entity: a virtual group of
// humans, by name and ID, in Namespace (by path, "/" for the root namespace).
// Status is "accepted" for the sponsor, "pending" for a handover no member of
// the group has accepted yet (AcceptedBy nil).
type EntitySponsor struct {
	Type       string        `json:"type"`
	Namespace  string        `json:"namespace"`
	Group      string        `json:"group"`
	GroupID    string        `json:"group_id"`
	AddedBy    SponsorActor  `json:"added_by"`
	AddedAt    time.Time     `json:"added_at"`
	AcceptedBy *SponsorActor `json:"accepted_by"`
	AcceptedAt time.Time     `json:"accepted_at"`
	Status     string        `json:"status"`
}

// SponsorActor is who proposed or accepted a sponsor: the person's native
// identity on an auth mount (Mount by path, MountAccessor, Alias) and their
// principal. A token no mount issued, root's, has the principal only.
type SponsorActor struct {
	Mount         string `json:"mount"`
	MountAccessor string `json:"mount_accessor"`
	Alias         string `json:"alias"`
	Principal     string `json:"principal"`
}

// SponsorRef names a sponsor group: its name, and the namespace it lives in
// by path, the entity's (when empty) or one of its ancestors ("/" for the
// root namespace).
type SponsorRef struct {
	Group     string `json:"group"`
	Namespace string `json:"namespace,omitempty"`
}

// Body returns the request body naming r.
func (r SponsorRef) Body() map[string]any {
	out := map[string]any{"group": r.Group}
	if r.Namespace != "" {
		out["namespace"] = r.Namespace
	}
	return out
}

// EntityAlias is a native identity an entity claims: Name as the auth mount
// derives it from a credential, the mount by accessor, and by its current
// path (Mount; empty when the mount was disabled since).
type EntityAlias struct {
	Mount         string    `json:"mount"`
	MountAccessor string    `json:"mount_accessor"`
	Name          string    `json:"name"`
	CreatedAt     time.Time `json:"created_at"`
}

// AliasRef names a native identity: the auth mount by path (Mount, e.g.
// "auth/kubernetes/") or by accessor (MountAccessor, which also names a mount
// disabled since; release and lookup only), and its Name.
type AliasRef struct {
	Mount         string `json:"mount,omitempty"`
	MountAccessor string `json:"mount_accessor,omitempty"`
	Name          string `json:"name"`
}

// Body returns the request body naming a: its mount and its name.
func (a AliasRef) Body() map[string]any {
	out := map[string]any{"name": a.Name}
	if a.Mount != "" {
		out["mount"] = a.Mount
	}
	if a.MountAccessor != "" {
		out["mount_accessor"] = a.MountAccessor
	}
	return out
}

// EntityInput is the body of an entity create or update. On update a nil or
// empty field keeps the stored value and a set one replaces it. Kind is set
// on create only; Aliases are claimed on create only (afterwards through
// ClaimAlias and RemoveAlias); NewName renames on update. The sponsor changes
// through ProposeSponsor and RemoveSponsor, the state through SetEntityState.
type EntityInput struct {
	Kind        string
	Description *string
	Profile     map[string]string // purpose, runtime, publisher
	Metadata    map[string]string
	Aliases     []AliasRef
	NewName     string

	// ExpectedHash, on update, applies the write only if the entity still has
	// this hash (Entity.Hash from an earlier read).
	ExpectedHash string
}

func (in *EntityInput) body() map[string]any {
	out := map[string]any{}
	if in == nil {
		return out
	}
	if in.Kind != "" {
		out["kind"] = in.Kind
	}
	if in.Description != nil {
		out["description"] = *in.Description
	}
	if in.Profile != nil {
		out["profile"] = in.Profile
	}
	if in.Metadata != nil {
		out["metadata"] = in.Metadata
	}
	if in.Aliases != nil {
		aliases := make([]map[string]any, len(in.Aliases))
		for i, a := range in.Aliases {
			aliases[i] = a.Body()
		}
		out["aliases"] = aliases
	}
	if in.NewName != "" {
		out["new_name"] = in.NewName
	}
	if in.ExpectedHash != "" {
		out["expected_hash"] = in.ExpectedHash
	}
	return out
}

// EntityFilter selects entities in ListEntities; zero fields select
// everything.
type EntityFilter struct {
	Kind         string
	State        string
	Sponsor      string // the name of the sponsor group
	SponsorState string // "accepted" (has a sponsor) or "pending" (has a handover)
	GovernedBy   string
	Ungoverned   bool // no sponsor or no description
	Orphaned     bool // a native identity on an auth mount that no longer exists
}

// AliasClaim is what a claim returns: the native identity now claimed by
// Entity, and the entity it was taken from (MovedFrom), if any.
type AliasClaim struct {
	Entity        string `json:"entity"`
	Mount         string `json:"mount"`
	MountAccessor string `json:"mount_accessor"`
	Name          string `json:"name"`
	MovedFrom     string `json:"moved_from,omitempty"`
}

// AliasLookup is the entity that claims a native identity.
type AliasLookup struct {
	Entity     string `json:"entity"`
	EntityID   string `json:"entity_id"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	GovernedBy string `json:"governed_by"`
}

// decodeData decodes a response's data into out.
func decodeData(v any, out any, what string) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("failed to decode %s: %w", what, err)
	}
	return nil
}

// dataRequest sends r and decodes the response's data into out.
func (c *Sys) dataRequest(ctx context.Context, r *Request, out any, what string) error {
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	resource, err := ParseResource(resp.Body)
	if err != nil {
		return err
	}
	if resource == nil || resource.Data == nil {
		return errors.New("data from server response is empty")
	}
	return decodeData(resource.Data, out, what)
}

func (c *Sys) entityRequest(ctx context.Context, r *Request) (*Entity, error) {
	var e Entity
	if err := c.dataRequest(ctx, r, &e, "entity"); err != nil {
		return nil, err
	}
	return &e, nil
}

// CreateEntity creates the entity name in the client's namespace, claiming
// the native identities input lists.
func (c *Sys) CreateEntity(name string, input *EntityInput) (*Entity, error) {
	return c.CreateEntityWithContext(context.Background(), name, input)
}

// CreateEntityWithContext creates the entity name with context.
func (c *Sys) CreateEntityWithContext(ctx context.Context, name string, input *EntityInput) (*Entity, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/identity/entity/%s", name))
	if err := r.SetJSONBody(input.body()); err != nil {
		return nil, err
	}
	return c.entityRequest(ctx, r)
}

// ReadEntity reads the entity name.
func (c *Sys) ReadEntity(name string) (*Entity, error) {
	return c.ReadEntityWithContext(context.Background(), name)
}

// ReadEntityWithContext reads the entity name with context.
func (c *Sys) ReadEntityWithContext(ctx context.Context, name string) (*Entity, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/identity/entity/%s", name))
	return c.entityRequest(ctx, r)
}

// ReadEntityByID reads the entity with id, which never changes.
func (c *Sys) ReadEntityByID(id string) (*Entity, error) {
	return c.ReadEntityByIDWithContext(context.Background(), id)
}

// ReadEntityByIDWithContext reads the entity with id with context.
func (c *Sys) ReadEntityByIDWithContext(ctx context.Context, id string) (*Entity, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/identity/entity/id/%s", id))
	return c.entityRequest(ctx, r)
}

// UpdateEntity updates the entity name with the fields input sets.
func (c *Sys) UpdateEntity(name string, input *EntityInput) (*Entity, error) {
	return c.UpdateEntityWithContext(context.Background(), name, input)
}

// UpdateEntityWithContext updates the entity name with context.
func (c *Sys) UpdateEntityWithContext(ctx context.Context, name string, input *EntityInput) (*Entity, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPut, fmt.Sprintf("/v1/sys/identity/entity/%s", name))
	if err := r.SetJSONBody(input.body()); err != nil {
		return nil, err
	}
	return c.entityRequest(ctx, r)
}

// ProposeSponsor proposes the group ref names as the sponsor of the entity
// name. When the caller is a member of the group it is the sponsor at once;
// otherwise it is a pending handover, which a member accepts, and the
// returned entity's Warnings say so. A non-empty expectedHash applies it only
// if the entity still has that hash.
func (c *Sys) ProposeSponsor(name string, ref SponsorRef, expectedHash string) (*Entity, error) {
	return c.ProposeSponsorWithContext(context.Background(), name, ref, expectedHash)
}

// ProposeSponsorWithContext proposes the sponsor ref with context.
func (c *Sys) ProposeSponsorWithContext(ctx context.Context, name string, ref SponsorRef, expectedHash string) (*Entity, error) {
	body := ref.Body()
	if expectedHash != "" {
		body["expected_hash"] = expectedHash
	}
	return c.entityWrite(ctx, name, "sponsor", body)
}

// RemoveSponsor removes the sponsor of the entity name, which is ungoverned
// after it, or with pending cancels its pending handover.
func (c *Sys) RemoveSponsor(name string, pending bool, expectedHash string) (*Entity, error) {
	return c.RemoveSponsorWithContext(context.Background(), name, pending, expectedHash)
}

// RemoveSponsorWithContext removes the sponsor with context.
func (c *Sys) RemoveSponsorWithContext(ctx context.Context, name string, pending bool, expectedHash string) (*Entity, error) {
	body := map[string]any{}
	if pending {
		body["pending"] = true
	}
	if expectedHash != "" {
		body["expected_hash"] = expectedHash
	}
	return c.entityWrite(ctx, name, "sponsor/remove", body)
}

// SetEntityState moves the entity name to state: "active", "suspended" or
// "retired", which is final.
func (c *Sys) SetEntityState(name, state, expectedHash string) (*Entity, error) {
	return c.SetEntityStateWithContext(context.Background(), name, state, expectedHash)
}

// SetEntityStateWithContext sets the entity's state with context.
func (c *Sys) SetEntityStateWithContext(ctx context.Context, name, state, expectedHash string) (*Entity, error) {
	body := map[string]any{"state": state}
	if expectedHash != "" {
		body["expected_hash"] = expectedHash
	}
	return c.entityWrite(ctx, name, "state", body)
}

// SponsorRead reads the entity name as a member of its sponsor group, or of
// its pending handover's, signed in with a ticket and no role. Every refusal
// is the same 403, whatever its cause.
func (c *Sys) SponsorRead(name string) (*Entity, error) {
	return c.SponsorReadWithContext(context.Background(), name)
}

// SponsorReadWithContext reads a sponsored entity with context.
func (c *Sys) SponsorReadWithContext(ctx context.Context, name string) (*Entity, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, fmt.Sprintf("/v1/sys/identity/sponsor/%s", name))
	return c.entityRequest(ctx, r)
}

// SponsorSuspend suspends the entity name as a member of its sponsor group.
func (c *Sys) SponsorSuspend(name string) (*Entity, error) {
	return c.SponsorSuspendWithContext(context.Background(), name)
}

// SponsorSuspendWithContext suspends a sponsored entity with context.
func (c *Sys) SponsorSuspendWithContext(ctx context.Context, name string) (*Entity, error) {
	return c.sponsorWrite(ctx, name, "suspend", map[string]any{})
}

// SponsorHandover hands the entity name over to the group ref names, as a
// member of its sponsor group: accepted at once when the caller is a member of
// that group too, a pending handover otherwise.
func (c *Sys) SponsorHandover(name string, ref SponsorRef) (*Entity, error) {
	return c.SponsorHandoverWithContext(context.Background(), name, ref)
}

// SponsorHandoverWithContext hands a sponsored entity over with context.
func (c *Sys) SponsorHandoverWithContext(ctx context.Context, name string, ref SponsorRef) (*Entity, error) {
	return c.sponsorWrite(ctx, name, "handover", ref.Body())
}

// SponsorCancel cancels the pending handover of the entity name, as a member
// of its sponsor group.
func (c *Sys) SponsorCancel(name string) (*Entity, error) {
	return c.SponsorCancelWithContext(context.Background(), name)
}

// SponsorCancelWithContext cancels a sponsored entity's handover with context.
func (c *Sys) SponsorCancelWithContext(ctx context.Context, name string) (*Entity, error) {
	return c.sponsorWrite(ctx, name, "handover", map[string]any{"cancel": true})
}

// SponsorAccept accepts the pending handover of the entity name, as a member
// of the pending group: it becomes the entity's sponsor.
func (c *Sys) SponsorAccept(name string) (*Entity, error) {
	return c.SponsorAcceptWithContext(context.Background(), name)
}

// SponsorAcceptWithContext accepts a sponsor handover with context.
func (c *Sys) SponsorAcceptWithContext(ctx context.Context, name string) (*Entity, error) {
	return c.sponsorWrite(ctx, name, "accept", map[string]any{})
}

// sponsorWrite posts body to the verb of the sponsor path of the entity name.
func (c *Sys) sponsorWrite(ctx context.Context, name, verb string, body map[string]any) (*Entity, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/identity/sponsor/%s/%s", name, verb))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}
	return c.entityRequest(ctx, r)
}

// entityWrite posts body to the sub-path of the entity name and returns the
// entity the server answers with.
func (c *Sys) entityWrite(ctx context.Context, name, sub string, body map[string]any) (*Entity, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/identity/entity/%s/%s", name, sub))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}
	return c.entityRequest(ctx, r)
}

// DeleteEntity deletes the entity name, releasing the native identities it
// claims, and returns the server's warnings (nil when there are none). A
// non-empty expectedHash deletes it only if it still has that hash. A retired
// entity is deleted only with force: its native identities are unclaimed
// again, which a warning says.
func (c *Sys) DeleteEntity(name, expectedHash string, force bool) ([]string, error) {
	return c.DeleteEntityWithContext(context.Background(), name, expectedHash, force)
}

// DeleteEntityWithContext deletes the entity name with context.
func (c *Sys) DeleteEntityWithContext(ctx context.Context, name, expectedHash string, force bool) ([]string, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodDelete, fmt.Sprintf("/v1/sys/identity/entity/%s", name))
	if expectedHash != "" {
		r.Params.Set("expected_hash", expectedHash)
	}
	if force {
		r.Params.Set("force", "true")
	}
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	resource, perr := ParseResource(resp.Body)
	if perr != nil || resource == nil || resource.Data == nil {
		// The entity is deleted; a body that does not parse only loses warnings.
		return nil, nil
	}
	return parseWarnings(resource.Data["warnings"]), nil
}

// ListEntities lists the entities of the client's namespace that f selects
// (nil selects every one), sorted by name.
func (c *Sys) ListEntities(f *EntityFilter) ([]*Entity, error) {
	return c.ListEntitiesWithContext(context.Background(), f)
}

// ListEntitiesWithContext lists the entities with context.
func (c *Sys) ListEntitiesWithContext(ctx context.Context, f *EntityFilter) ([]*Entity, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodGet, "/v1/sys/identity/entity")
	r.Params.Set("warden-list", "true")
	if f != nil {
		for k, v := range map[string]string{
			"kind": f.Kind, "state": f.State, "sponsor": f.Sponsor, "sponsor_state": f.SponsorState, "governed_by": f.GovernedBy,
		} {
			if v != "" {
				r.Params.Set(k, v)
			}
		}
		if f.Ungoverned {
			r.Params.Set("ungoverned", "true")
		}
		if f.Orphaned {
			r.Params.Set("orphaned", "true")
		}
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
	entities := []*Entity{}
	if resource == nil || resource.Data == nil {
		return entities, nil
	}
	items, _ := resource.Data["entities"].([]any)
	for _, item := range items {
		var e Entity
		if err := decodeData(item, &e, "entity"); err != nil {
			return nil, err
		}
		entities = append(entities, &e)
	}
	return entities, nil
}

// ClaimAlias claims the native identity ref for the entity name. One another
// entity claims is refused unless move is set, or that entity is retired; it
// is then taken from it (AliasClaim.MovedFrom). ref names its mount by path.
func (c *Sys) ClaimAlias(name string, ref AliasRef, move bool) (*AliasClaim, error) {
	return c.ClaimAliasWithContext(context.Background(), name, ref, move)
}

// ClaimAliasWithContext claims the native identity ref with context.
func (c *Sys) ClaimAliasWithContext(ctx context.Context, name string, ref AliasRef, move bool) (*AliasClaim, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	body := ref.Body()
	if move {
		body["move"] = true
	}
	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/identity/entity/%s/alias", name))
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}
	var claim AliasClaim
	if err := c.dataRequest(ctx, r, &claim, "claim"); err != nil {
		return nil, err
	}
	return &claim, nil
}

// RemoveAlias releases the native identity ref from the entity name: it is
// unclaimed again. A retired entity's are refused: move them instead.
func (c *Sys) RemoveAlias(name string, ref AliasRef) error {
	return c.RemoveAliasWithContext(context.Background(), name, ref)
}

// RemoveAliasWithContext releases the native identity ref with context.
func (c *Sys) RemoveAliasWithContext(ctx context.Context, name string, ref AliasRef) error {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, fmt.Sprintf("/v1/sys/identity/entity/%s/alias/remove", name))
	if err := r.SetJSONBody(ref.Body()); err != nil {
		return err
	}
	resp, err := c.c.rawRequestWithContext(ctx, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// LookupAlias returns the entity that claims the native identity ref. An
// unclaimed one answers a 404 (an error).
func (c *Sys) LookupAlias(ref AliasRef) (*AliasLookup, error) {
	return c.LookupAliasWithContext(context.Background(), ref)
}

// LookupAliasWithContext looks the native identity ref up with context.
func (c *Sys) LookupAliasWithContext(ctx context.Context, ref AliasRef) (*AliasLookup, error) {
	ctx, cancelFunc := c.c.withConfiguredTimeout(ctx)
	defer cancelFunc()

	r := c.c.NewRequest(http.MethodPost, "/v1/sys/identity/lookup")
	if err := r.SetJSONBody(ref.Body()); err != nil {
		return nil, err
	}
	var l AliasLookup
	if err := c.dataRequest(ctx, r, &l, "lookup"); err != nil {
		return nil, err
	}
	return &l, nil
}
