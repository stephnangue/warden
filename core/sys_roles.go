package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/stephnangue/warden/framework"
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
				"A policy or credential spec that does not exist yet is accepted with a warning.",
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
	}

	warnings, err := b.core.roleStore.Create(ctx, role)
	if err != nil {
		return roleErrorResponse(name, err), nil
	}
	return b.respondCreated(roleResponseData(role, role.Hash(), warnings)), nil
}

// handleRoleRead handles GET sys/roles/<name>.
func (b *SystemBackend) handleRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, hash, err := b.core.roleStore.Get(ctx, name)
	if err != nil {
		return roleErrorResponse(name, err), nil
	}
	return b.respondSuccess(roleResponseData(role, hash, nil)), nil
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

	for attempt := 1; ; attempt++ {
		role, hash, err := b.core.roleStore.Get(ctx, name)
		if err != nil {
			return roleErrorResponse(name, err), nil
		}
		if expected != "" && expected != hash {
			return roleErrorResponse(name, ErrRoleChanged), nil
		}
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
}

// handleRoleDelete handles DELETE sys/roles/<name>, conditional on
// expected_hash (a query parameter) when set.
func (b *SystemBackend) handleRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := b.core.roleStore.Delete(ctx, name, d.Get("expected_hash").(string)); err != nil {
		return roleErrorResponse(name, err), nil
	}
	return b.respondSuccess(map[string]any{
		"name":    name,
		"message": fmt.Sprintf("Successfully deleted role %s", name),
	}), nil
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

	keys := make([]string, 0, len(roles))
	items := make([]map[string]any, 0, len(roles))
	for _, r := range roles {
		if providerPath != "" && r.ProviderPath != providerPath {
			continue
		}
		keys = append(keys, r.Name)
		items = append(items, roleToMap(r))
	}
	return b.respondSuccess(map[string]any{
		"keys":  keys,
		"roles": items,
	}), nil
}
