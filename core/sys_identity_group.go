package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// pathIdentityGroups returns the paths for namespace groups:
// sys/identity/group/<name> (CRUD) and sys/identity/group (LIST), every
// operation needing sudo (PathsSpecial.Root), and sys/identity/usage (READ), a
// normal ACL path. Each is scoped to the namespace of the request.
func (b *SystemBackend) pathIdentityGroups() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "identity/group/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the group",
					Required:    true,
				},
				"type": {
					Type: framework.TypeString,
					Description: `Where membership comes from: "virtual" (computed from the facts an auth mount verified). ` +
						"Required on every write (create, update, and delete, where it is a query parameter) and never changes: " +
						"a write naming another type than the stored one is refused. Optional on read, where it must match too.",
				},
				"description": {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("What the group is for (at most %d bytes)", logical.MaxGroupDescriptionBytes),
				},
				"roles": {
					Type:        framework.TypeCommaStringSlice,
					Description: fmt.Sprintf("Roles membership grants, by name (at most %d)", logical.MaxGroupRoles),
				},
				"rules": {
					Type: framework.TypeSlice,
					Description: "Rules a caller's verified facts must satisfy, any one of them (virtual groups). " +
						"A rule is a set of selectors, each a fact name with the values it may take (a list, or one string); " +
						"every selector must match one of its values. " +
						`Every rule must include a "mount" selector listing the auth mounts it trusts (e.g. "auth/kubernetes/"). ` +
						`A value holding an unescaped "*" or "?" is a glob.`,
				},
				"valid_until": {
					Type: framework.TypeString,
					Description: "RFC 3339 instant after which the group grants nothing (e.g. 2026-12-31T23:59:59Z); " +
						"it still grants at that instant. Empty for no end.",
				},
				"metadata": {
					Type:        framework.TypeKVPairs,
					Description: fmt.Sprintf("Free-form string labels (at most %d keys)", logical.MaxRoleMetadataKeys),
				},
				"members": {
					Type:        framework.TypeSlice,
					Description: "Not valid on a virtual group",
				},
				"link": {
					Type:        framework.TypeMap,
					Description: "Not valid on a virtual group",
				},
				"expected_hash": {
					Type:        framework.TypeString,
					Description: "Apply the update or delete only if the group still has this hash (from a read)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleGroupCreate,
					Summary:  "Create a group",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleGroupRead,
					Summary:  "Read a group",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleGroupUpdate,
					Summary:  "Update a group; fields left out keep their value",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleGroupDelete,
					Summary:  "Delete a group",
				},
			},
			HelpSynopsis: "Manage namespace groups",
			HelpDescription: "A group grants roles to its members. A virtual group's members are the callers whose verified " +
				"facts match one of its rules, through one of the auth mounts the rule's \"mount\" selector lists. A role " +
				"that does not exist yet, or a fact no listed mount produces, is accepted with a warning. Responses carry " +
				"rule_count and selector_count, what the group adds to the namespace's usage.",
		},
		{
			Pattern: "identity/group/?$",
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeString,
					Description: "List only the groups that grant this role",
				},
				"type": {
					Type:        framework.TypeString,
					Description: "List only the groups of this type",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleGroupList,
					Summary:  "List the namespace's groups",
				},
			},
			HelpSynopsis:    "List namespace groups",
			HelpDescription: "List every group of the namespace, optionally only those granting one role or of one type.",
		},
		{
			// A normal ACL path, not sudo: only the group paths are root paths.
			Pattern: "identity/usage$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleIdentityUsage,
					Summary:  "Read the namespace's identity usage",
				},
			},
			HelpSynopsis: "Read the namespace's identity usage",
			HelpDescription: "Count the namespace's identity objects by kind against their caps. groups.total counts " +
				"every group; groups.virtual counts virtual groups and the selectors of their rules (\"mount\" " +
				"included) against max and max_selectors. identities counts the entities against max_entities, and " +
				"the native identities they claim.",
		},
	}
}

// groupToMap renders a group for a response. Every key is present, so the
// shape is the same whichever fields the group sets; rules render as written.
// rule_count and selector_count are what the group adds to the namespace's
// usage.
func groupToMap(g *logical.Group) map[string]any {
	roles := g.Roles
	if roles == nil {
		roles = []string{}
	}
	rules := make([]map[string][]string, len(g.Rules))
	for i, r := range g.Rules {
		rules[i] = r
	}
	metadata := g.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	validUntil := ""
	if !g.ValidUntil.IsZero() {
		validUntil = g.ValidUntil.UTC().Format(time.RFC3339Nano)
	}
	return map[string]any{
		"id":             g.ID,
		"name":           g.Name,
		"type":           string(g.Type),
		"description":    g.Description,
		"roles":          roles,
		"rules":          rules,
		"rule_count":     len(g.Rules),
		"selector_count": g.SelectorCount(),
		"valid_until":    validUntil,
		"metadata":       metadata,
		"created_at":     g.CreatedAt,
		"updated_at":     g.UpdatedAt,
	}
}

func groupResponseData(g *logical.Group, hash string, warnings []string) map[string]any {
	data := groupToMap(g)
	data["hash"] = hash
	appendWarnings(data, warnings...)
	return data
}

// groupErrorResponse maps an identity store error to its response.
func groupErrorResponse(name string, err error) *logical.Response {
	switch {
	case errors.As(err, new(*GroupTypeMismatchError)):
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error()))
	case errors.Is(err, ErrGroupNotFound):
		return logical.ErrorResponse(logical.ErrNotFoundf("group %q not found", name))
	case errors.Is(err, ErrGroupAlreadyExists):
		return logical.ErrorResponse(logical.ErrConflictf("group %q already exists", name))
	case errors.Is(err, ErrGroupChanged):
		return logical.ErrorResponse(logical.ErrConflictf(
			"group %q changed since it was read (expected_hash no longer matches); read it again and retry", name))
	case errors.Is(err, ErrTooManyVirtualGroups), errors.Is(err, ErrTooManySelectors):
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error()))
	case errors.Is(err, ErrIdentityStoreNotLoaded):
		return logical.ErrorResponse(logical.ErrServiceUnavailable(err.Error()))
	}
	return logical.ErrorResponse(err)
}

// refuseOtherTypeFields refuses a write carrying a field that belongs to
// another group type.
func refuseOtherTypeFields(d *framework.FieldData, t logical.GroupType) error {
	for _, f := range []string{"members", "link"} {
		if _, ok := d.GetOk(f); ok {
			return logical.ErrBadRequestf("%q is not valid on a %s group", f, t)
		}
	}
	return nil
}

// requestType returns the type a request names, or "" when it names none. A
// name that is no group type is refused.
func requestType(d *framework.FieldData) (logical.GroupType, error) {
	v, ok := d.GetOk("type")
	if !ok || v.(string) == "" {
		return "", nil
	}
	t, err := logical.ParseGroupType(v.(string))
	if err != nil {
		return "", logical.ErrBadRequest(err.Error())
	}
	return t, nil
}

// errGroupTypeRequired refuses a write that names no type. Every group write
// carries it, so a policy condition on request.data.type can tell who may
// write which type of group.
func errGroupTypeRequired(op string) error {
	return logical.ErrBadRequestf("type is required on %s: every group write names the group's type", op)
}

// parseRules converts the rules field of a write: a list of objects, each a
// set of selectors mapping a fact name to a list of strings, or to one string
// standing for a one-element list.
func parseRules(raw []any) ([]logical.GroupRule, error) {
	out := make([]logical.GroupRule, 0, len(raw))
	for i, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, logical.ErrBadRequestf("rules[%d]: must be an object of selectors (fact name to values), got %T", i, item)
		}
		rule := make(logical.GroupRule, len(m))
		for name, v := range m {
			values, err := stringList(v)
			if err != nil {
				return nil, logical.ErrBadRequestf("rules[%d]: selector %q: %v", i, name, err)
			}
			rule[name] = values
		}
		out = append(out, rule)
	}
	return out, nil
}

func stringList(v any) ([]string, error) {
	switch t := v.(type) {
	case string:
		return []string{t}, nil
	case []string:
		return t, nil
	case []any:
		out := make([]string, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("values must be strings, got %T", e)
			}
			out[i] = s
		}
		return out, nil
	}
	return nil, fmt.Errorf("must be a string or a list of strings, got %T", v)
}

// parseValidUntil reads a valid_until value: an RFC 3339 instant, or "" for
// no end.
func parseValidUntil(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, logical.ErrBadRequestf(
			"valid_until must be an RFC 3339 timestamp (e.g. 2026-12-31T23:59:59Z), got %q", s)
	}
	return t.UTC(), nil
}

// mergeGroupFields writes onto g every field present in the request. An empty
// type counts as left out; an empty valid_until clears it.
func mergeGroupFields(g *logical.Group, d *framework.FieldData) error {
	if v, ok := d.GetOk("type"); ok && v.(string) != "" {
		g.Type = logical.GroupType(v.(string))
	}
	if v, ok := d.GetOk("description"); ok {
		g.Description = v.(string)
	}
	if v, ok := d.GetOk("roles"); ok {
		g.Roles = v.([]string)
	}
	if v, ok := d.GetOk("rules"); ok {
		rules, err := parseRules(v.([]any))
		if err != nil {
			return err
		}
		g.Rules = rules
	}
	if v, ok := d.GetOk("valid_until"); ok {
		t, err := parseValidUntil(v.(string))
		if err != nil {
			return err
		}
		g.ValidUntil = t
	}
	if v, ok := d.GetOk("metadata"); ok {
		g.Metadata = v.(map[string]string)
	}
	return nil
}

// handleGroupCreate handles POST sys/identity/group/<name>.
func (b *SystemBackend) handleGroupCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if d.Get("expected_hash").(string) != "" {
		return logical.ErrorResponse(logical.ErrBadRequest(
			"expected_hash applies to an update or a delete; a create has no earlier version")), nil
	}
	g := &logical.Group{Name: name}
	if err := mergeGroupFields(g, d); err != nil {
		return logical.ErrorResponse(err), nil
	}
	if g.Type == logical.GroupTypeVirtual {
		if err := refuseOtherTypeFields(d, g.Type); err != nil {
			return logical.ErrorResponse(err), nil
		}
	}

	warnings, err := b.core.identityStore.CreateGroup(ctx, g)
	if err != nil {
		return groupErrorResponse(name, err), nil
	}
	return b.respondCreated(groupResponseData(g, g.Hash(), warnings)), nil
}

// handleGroupRead handles GET sys/identity/group/<name>.
func (b *SystemBackend) handleGroupRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	t, err := requestType(d)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	g, hash, err := b.core.identityStore.GetGroup(ctx, name)
	if err != nil {
		return groupErrorResponse(name, err), nil
	}
	if t != "" && t != g.Type {
		return groupErrorResponse(name, &GroupTypeMismatchError{Name: name, Stored: g.Type}), nil
	}
	return b.respondSuccess(groupResponseData(g, hash, nil)), nil
}

// handleGroupUpdate handles PUT sys/identity/group/<name>. A field present in
// the request replaces the stored value; a field left out keeps it. type is
// required and must equal the stored type. The write applies
// only to the version it was merged onto, and, when expected_hash is set, only
// if that version is the one the caller read.
//
// Without expected_hash the caller asked for no particular version, so a write
// that loses to a concurrent one is merged onto the new version and tried once
// more before the conflict is reported.
func (b *SystemBackend) handleGroupUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	expected := d.Get("expected_hash").(string)
	t, err := requestType(d)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	if t == "" {
		return logical.ErrorResponse(errGroupTypeRequired("update")), nil
	}

	for attempt := 1; ; attempt++ {
		g, hash, err := b.core.identityStore.GetGroup(ctx, name)
		if err != nil {
			return groupErrorResponse(name, err), nil
		}
		if expected != "" && expected != hash {
			return groupErrorResponse(name, ErrGroupChanged), nil
		}
		stored := g.Type
		if t != stored {
			return groupErrorResponse(name, &GroupTypeMismatchError{Name: name, Stored: stored}), nil
		}
		if err := mergeGroupFields(g, d); err != nil {
			return logical.ErrorResponse(err), nil
		}
		if err := refuseOtherTypeFields(d, stored); err != nil {
			return logical.ErrorResponse(err), nil
		}

		warnings, err := b.core.identityStore.UpdateGroup(ctx, g, hash)
		if errors.Is(err, ErrGroupChanged) && expected == "" {
			if attempt < 2 {
				continue
			}
			return logical.ErrorResponse(logical.ErrConflictf(
				"group %q changed concurrently; read it again and retry", name)), nil
		}
		if err != nil {
			return groupErrorResponse(name, err), nil
		}
		return b.respondSuccess(groupResponseData(g, g.Hash(), warnings)), nil
	}
}

// handleGroupDelete handles DELETE sys/identity/group/<name>. type (a query
// parameter) is required and must equal the stored type; expected_hash (a
// query parameter) makes the delete conditional when set.
func (b *SystemBackend) handleGroupDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	t, err := requestType(d)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	if t == "" {
		return logical.ErrorResponse(errGroupTypeRequired("delete")), nil
	}
	if err := b.core.identityStore.DeleteGroup(ctx, name, t, d.Get("expected_hash").(string)); err != nil {
		return groupErrorResponse(name, err), nil
	}
	return b.respondSuccess(map[string]any{
		"name":    name,
		"message": fmt.Sprintf("Successfully deleted group %s", name),
	}), nil
}

// handleGroupList handles LIST sys/identity/group. It returns the names under
// "keys" and the groups themselves (with their hashes) under "groups", both
// sorted by name; ?role= keeps only the groups granting that role, ?type= only
// the groups of that type.
func (b *SystemBackend) handleGroupList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	t, err := requestType(d)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	groups, hashes, err := b.core.identityStore.ListGroups(ctx, d.Get("role").(string))
	if err != nil {
		return groupErrorResponse("", err), nil
	}
	keys := make([]string, 0, len(groups))
	items := make([]map[string]any, 0, len(groups))
	for i, g := range groups {
		if t != "" && g.Type != t {
			continue
		}
		item := groupToMap(g)
		item["hash"] = hashes[i]
		keys = append(keys, g.Name)
		items = append(items, item)
	}
	return b.respondSuccess(map[string]any{
		"keys":   keys,
		"groups": items,
	}), nil
}

// handleIdentityUsage handles GET sys/identity/usage: the namespace's identity
// objects counted by kind, against their caps, one top-level key per kind.
func (b *SystemBackend) handleIdentityUsage(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	usage, err := b.core.identityStore.Usage(ctx)
	if err != nil {
		return groupErrorResponse("", err), nil
	}
	return b.respondSuccess(map[string]any{
		"groups":     usage.Groups,
		"identities": usage.Identities,
	}), nil
}
