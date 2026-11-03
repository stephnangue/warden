package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// pathRoles returns the paths for namespace roles: sys/roles/<name> (CRUD) and
// sys/roles (LIST). Every operation needs sudo (PathsSpecial.Root); a role is
// scoped to the namespace of the request.
func (b *SystemBackend) pathRoles() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("What the role is for, shown to agents by discovery (at most %d bytes)", logical.MaxRoleDescriptionBytes),
				},
				"policies": {
					Type:        framework.TypeCommaStringSlice,
					Description: "Policies a caller running under the role holds",
				},
				"cred_spec_name": {
					Type:        framework.TypeString,
					Description: "Credential spec a caller running under the role is served",
				},
				"skill": {
					Type:        framework.TypeString,
					Description: "Name of the skill that teaches an agent to use this role",
				},
				"provider_path": {
					Type:        framework.TypeString,
					Description: "Mount path of the provider this role is used with, relative to the namespace (e.g. aws/)",
				},
				"metadata": {
					Type:        framework.TypeKVPairs,
					Description: fmt.Sprintf("Free-form string labels (at most %d keys)", logical.MaxRoleMetadataKeys),
				},
				"governed_only": {
					Type: framework.TypeBool,
					Description: "Grant the role through governed membership only: a static group listing a governed, " +
						"active entity. No virtual group grants it, so neither an unclaimed agent nor a human holds it, " +
						"and a virtual group listing it is refused at write. Defaults to false.",
				},
				"expected_hash": {
					Type:        framework.TypeString,
					Description: "Apply the update or delete only if the role still has this hash (from a read)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleRoleCreate,
					Summary:  "Create a role",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRoleRead,
					Summary:  "Read a role",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRoleUpdate,
					Summary:  "Update a role; fields left out keep their value",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRoleDelete,
					Summary:  "Delete a role",
				},
			},
			HelpSynopsis: "Manage namespace roles",
			HelpDescription: "A role names what a caller running under it may do (policies, cred_spec_name) " +
				"and how discovery describes it (description, skill, provider_path). " +
				"A policy or credential spec that does not exist yet is accepted with a warning. " +
				"governed_only restricts it to static groups of governed entities; the write warns, naming the " +
				"virtual groups that list it and no longer grant it.",
		},
		{
			Pattern: "roles/?$",
			Fields: map[string]*framework.FieldSchema{
				"provider_path": {
					Type:        framework.TypeString,
					Description: "List only the roles used with this provider mount path",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleRoleList,
					Summary:  "List the namespace's roles",
				},
			},
			HelpSynopsis:    "List namespace roles",
			HelpDescription: "List every role of the namespace, optionally only those used with one provider_path.",
		},
	}
}

// roleToMap renders a role for a response. Every key is present, so the shape
// is the same whichever fields the role sets.
func roleToMap(r *logical.Role) map[string]any {
	policies := r.Policies
	if policies == nil {
		policies = []string{}
	}
	metadata := r.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	return map[string]any{
		"name":           r.Name,
		"description":    r.Description,
		"policies":       policies,
		"cred_spec_name": r.CredSpecName,
		"skill":          r.Skill,
		"provider_path":  r.ProviderPath,
		"metadata":       metadata,
		"governed_only":  r.GovernedOnly,
		"created_at":     r.CreatedAt,
		"updated_at":     r.UpdatedAt,
	}
}

// roleResponseData is roleToMap plus the role's hash and any warnings.
func roleResponseData(r *logical.Role, hash string, warnings []string) map[string]any {
	data := roleToMap(r)
	data["hash"] = hash
	appendWarnings(data, warnings...)
	return data
}

// roleErrorResponse maps a role store error to its response.
func roleErrorResponse(name string, err error) *logical.Response {
	switch {
	case errors.Is(err, ErrRoleNotFound):
		return logical.ErrorResponse(logical.ErrNotFoundf("role %q not found", name))
	case errors.Is(err, ErrRoleAlreadyExists):
		return logical.ErrorResponse(logical.ErrConflictf("role %q already exists", name))
	case errors.Is(err, ErrRoleChanged):
		return logical.ErrorResponse(logical.ErrConflictf(
			"role %q changed since it was read (expected_hash no longer matches); read it again and retry", name))
	case errors.Is(err, ErrRoleStoreNotLoaded):
		return logical.ErrorResponse(logical.ErrServiceUnavailable(err.Error()))
	}
	return logical.ErrorResponse(err)
}

// handleRoleCreate handles POST sys/roles/<name>.
func (b *SystemBackend) handleRoleCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if d.Get("expected_hash").(string) != "" {
		return logical.ErrorResponse(logical.ErrBadRequest(
			"expected_hash applies to an update or a delete; a create has no earlier version")), nil
	}
	role := &logical.Role{
		Name:         name,
		Description:  d.Get("description").(string),
		Policies:     d.Get("policies").([]string),
		CredSpecName: d.Get("cred_spec_name").(string),
		Skill:        d.Get("skill").(string),
		ProviderPath: d.Get("provider_path").(string),
		Metadata:     d.Get("metadata").(map[string]string),
		GovernedOnly: d.Get("governed_only").(bool),
	}

	warnings, err := b.core.roleStore.Create(ctx, role)
	if err != nil {
		return roleErrorResponse(name, err), nil
	}
	warnings = append(warnings, b.governedOnlyWarnings(ctx, req, role, false)...)
	return b.respondCreated(roleResponseData(role, role.Hash(), warnings)), nil
}

// governedOnlyWarnings says what a governed_only role just written takes
// away: the virtual groups of its namespace that list it and no longer grant
// it, and the writer's own request when it holds the role through one. A
// role write is never refused for it; a write of one of those groups is,
// until the role leaves its list.
//
// It warns only when the write sets the flag (wasGovernedOnly is the stored
// value before it, false on a create): an edit of a role already flagged
// takes nothing more away. On a create the writer cannot hold the role yet.
func (b *SystemBackend) governedOnlyWarnings(ctx context.Context, req *logical.Request, role *logical.Role, wasGovernedOnly bool) []string {
	if !role.GovernedOnly || wasGovernedOnly {
		return nil
	}
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil
	}
	idx := b.core.identityStore.namespaceIndex(ns.ID)
	var virtual []string
	for _, name := range idx.listing(role.Name) {
		if idx.groupsByName[name].Type == logical.GroupTypeVirtual {
			virtual = append(virtual, name)
		}
	}
	var warnings []string
	if len(virtual) > 0 {
		listed := virtual[:min(len(virtual), maxNamedInWarning)]
		groups := "virtual groups list it and no longer grant it"
		if len(virtual) == 1 {
			groups = "virtual group lists it and no longer grants it"
		}
		msg := fmt.Sprintf("role %q is governed_only; %d %s: %s", role.Name, len(virtual), groups, strings.Join(listed, ", "))
		if more := len(virtual) - len(listed); more > 0 {
			msg += fmt.Sprintf(" and %d more", more)
		}
		warnings = append(warnings, msg)
	}
	if rg := req.RoleGrant(); rg != nil && rg.Granted() && rg.RoleName == role.Name && rg.GroupType == logical.GroupTypeVirtual {
		warnings = append(warnings, fmt.Sprintf(
			"the writer's own request holds role %q through a virtual group; its next request under the role is refused", role.Name))
	}
	return warnings
}

// handleRoleRead handles GET sys/roles/<name>.
func (b *SystemBackend) handleRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	// A built-in, where the namespace has them, wins over a role stored under
	// its name by an earlier release, as it does at grant time.
	if i := builtinRoleIndex(name); i >= 0 {
		if ns, err := namespace.FromContext(ctx); err == nil && builtinRolesEnabled(ns.ID, ns) {
			return b.respondSuccess(builtinRoleData(i)), nil
		}
	}
	role, hash, err := b.core.roleStore.Get(ctx, name)
	if err != nil {
		return roleErrorResponse(name, err), nil
	}
	var warnings []string
	if isReservedRoleName(name) {
		warnings = append(warnings, legacyReservedRolesWarning(name))
	}
	return b.respondSuccess(roleResponseData(role, hash, warnings)), nil
}

// legacyReservedRolesWarning says why roles stored under reserved names, by a
// release before the names were reserved, still read and list: they grant
// nothing, and are kept only to be deleted.
func legacyReservedRolesWarning(names ...string) string {
	return fmt.Sprintf("stored under a name reserved for built-in roles, so it grants nothing; delete it: %s", strings.Join(names, ", "))
}

// builtinRoleData is the read of the built-in at index i: roleToMap, marked
// built-in, with the body it grants and its hash.
func builtinRoleData(i int) map[string]any {
	r := builtinRoles[i]
	data := roleToMap(r.role)
	data["builtin"] = true
	data["policy_document"] = strings.TrimLeft(r.body, "\n")
	data["hash"] = r.role.Hash()
	return data
}

// handleRoleUpdate handles PUT sys/roles/<name>. A field present in the request
// replaces the stored value, including with an empty one; a field left out
// keeps it. The write applies only to the version it was merged onto, and, when
// expected_hash is set, only if that version is the one the caller read.
//
// Without expected_hash the caller asked for no particular version, so a write
// that loses to a concurrent one is merged onto the new version and tried once
// more before the conflict is reported.
func (b *SystemBackend) handleRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	expected := d.Get("expected_hash").(string)

	// Before the read: a built-in is not stored, and a legacy role stored under
	// a reserved name is no longer writable, only deletable.
	if isReservedRoleName(name) {
		return logical.ErrorResponse(errReservedRoleName(name)), nil
	}

	for attempt := 1; ; attempt++ {
		role, hash, err := b.core.roleStore.Get(ctx, name)
		if err != nil {
			return roleErrorResponse(name, err), nil
		}
		if expected != "" && expected != hash {
			return roleErrorResponse(name, ErrRoleChanged), nil
		}
		wasGovernedOnly := role.GovernedOnly
		mergeRoleFields(role, d)

		warnings, err := b.core.roleStore.Update(ctx, role, hash)
		if errors.Is(err, ErrRoleChanged) && expected == "" {
			if attempt < 2 {
				continue
			}
			return logical.ErrorResponse(logical.ErrConflictf(
				"role %q changed concurrently; read it again and retry", name)), nil
		}
		if err != nil {
			return roleErrorResponse(name, err), nil
		}
		warnings = append(warnings, b.governedOnlyWarnings(ctx, req, role, wasGovernedOnly)...)
		return b.respondSuccess(roleResponseData(role, role.Hash(), warnings)), nil
	}
}

// mergeRoleFields writes onto role every field present in the request.
func mergeRoleFields(role *logical.Role, d *framework.FieldData) {
	if v, ok := d.GetOk("description"); ok {
		role.Description = v.(string)
	}
	if v, ok := d.GetOk("policies"); ok {
		role.Policies = v.([]string)
	}
	if v, ok := d.GetOk("cred_spec_name"); ok {
		role.CredSpecName = v.(string)
	}
	if v, ok := d.GetOk("skill"); ok {
		role.Skill = v.(string)
	}
	if v, ok := d.GetOk("provider_path"); ok {
		role.ProviderPath = v.(string)
	}
	if v, ok := d.GetOk("metadata"); ok {
		role.Metadata = v.(map[string]string)
	}
	if v, ok := d.GetOk("governed_only"); ok {
		role.GovernedOnly = v.(bool)
	}
}

// handleRoleDelete handles DELETE sys/roles/<name>, conditional on
// expected_hash (a query parameter) when set. Groups that still list the role
// keep it and are named in a warning: they grant nothing through it until a
// role of that name exists again.
func (b *SystemBackend) handleRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := b.core.roleStore.Delete(ctx, name, d.Get("expected_hash").(string)); err != nil {
		// A role stored under a built-in's name before the space was reserved
		// is deleted above; the built-in itself cannot be. Where the
		// namespace has no built-ins, there is nothing by that name.
		if errors.Is(err, ErrRoleNotFound) && isBuiltinRoleName(name) {
			if ns, nsErr := namespace.FromContext(ctx); nsErr == nil && builtinRolesEnabled(ns.ID, ns) {
				return logical.ErrorResponse(errReservedRoleName(name)), nil
			}
		}
		return roleErrorResponse(name, err), nil
	}
	data := map[string]any{
		"name":    name,
		"message": fmt.Sprintf("Successfully deleted role %s", name),
	}
	if ns, err := namespace.FromContext(ctx); err == nil && b.core.identityStore != nil {
		if groups := b.core.identityStore.GroupsListingRole(ns.ID, name); len(groups) > 0 {
			appendWarnings(data, fmt.Sprintf("groups still list %q: %s (they grant nothing until the role is re-created)",
				name, strings.Join(groups, ", ")))
		}
	}
	return b.respondSuccess(data), nil
}

// handleRoleList handles LIST sys/roles. It returns the names under "keys" and
// the roles themselves under "roles", both sorted by name.
func (b *SystemBackend) handleRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := b.core.roleStore.List(ctx)
	if err != nil {
		return roleErrorResponse("", err), nil
	}

	providerPath := d.Get("provider_path").(string)
	if providerPath != "" && !strings.HasSuffix(providerPath, "/") {
		providerPath += "/"
	}

	// The built-ins, where the namespace has them, listed among the stored
	// roles and in their place when a role was stored under a built-in's name.
	// None has a provider_path, so a provider_path filter leaves them out.
	builtins := false
	if ns, err := namespace.FromContext(ctx); err == nil {
		builtins = builtinRolesEnabled(ns.ID, ns) && providerPath == ""
	}
	type listed struct {
		name string
		item map[string]any
	}
	all := make([]listed, 0, len(roles)+len(builtinRoles))
	var legacy []string
	for _, r := range roles {
		if providerPath != "" && r.ProviderPath != providerPath {
			continue
		}
		// A stored record under a reserved name is named in the warning even
		// where the built-in it shadows is listed in its place: the warning
		// is the operator's only trace of it.
		if isReservedRoleName(r.Name) {
			legacy = append(legacy, r.Name)
		}
		if builtins && isBuiltinRoleName(r.Name) {
			continue
		}
		all = append(all, listed{r.Name, roleToMap(r)})
	}
	if builtins {
		for i := range builtinRoles {
			item := roleToMap(builtinRoles[i].role)
			item["builtin"] = true
			all = append(all, listed{builtinRoles[i].role.Name, item})
		}
		slices.SortFunc(all, func(a, b listed) int { return strings.Compare(a.name, b.name) })
	}
	keys := make([]string, 0, len(all))
	items := make([]map[string]any, 0, len(all))
	for _, l := range all {
		keys = append(keys, l.name)
		items = append(items, l.item)
	}
	data := map[string]any{
		"keys":  keys,
		"roles": items,
	}
	if len(legacy) > 0 {
		appendWarnings(data, legacyReservedRolesWarning(legacy...))
	}
	return b.respondSuccess(data), nil
}
