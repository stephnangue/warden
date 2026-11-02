package core

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logical"
)

// pathIdentityEntities returns the paths for namespace entities and the native
// identities they claim: sys/identity/entity/<name> (CRUD),
// sys/identity/entity (LIST), sys/identity/entity/id/<id> (READ), the alias
// paths of an entity, and sys/identity/lookup. Every one needs sudo
// (PathsSpecial.Root) and is scoped to the namespace of the request.
func (b *SystemBackend) pathIdentityEntities() []*framework.Path {
	mountField := &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `The auth mount the native identity is presented through, by path (e.g. "auth/kubernetes/")`,
		Required:    true,
	}
	// Releasing and looking up also take the mount by accessor, which still
	// names a mount disabled with force: the claims left on it.
	boundMountField := &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: `The auth mount the native identity is presented through, by path (e.g. "auth/kubernetes/"); or mount_accessor`,
	}
	accessorField := &framework.FieldSchema{
		Type: framework.TypeString,
		Description: "The auth mount by accessor, instead of mount: it also names a mount disabled since, " +
			"whose claims are listed with orphaned=true",
	}
	aliasField := &framework.FieldSchema{
		Type: framework.TypeString,
		Description: "The native identity, as the mount derives it from a credential (its alias_name_source), " +
			`e.g. "system:serviceaccount:billing:agent"`,
		Required: true,
	}
	expectedHashField := &framework.FieldSchema{
		Type:        framework.TypeString,
		Description: "Apply the write only if the entity still has this hash (from a read)",
	}
	return []*framework.Path{
		{
			Pattern: "identity/entity/?$",
			Fields: map[string]*framework.FieldSchema{
				"kind":    {Type: framework.TypeString, Description: "List only entities of this kind"},
				"state":   {Type: framework.TypeString, Description: "List only entities in this state"},
				"sponsor": {Type: framework.TypeString, Description: "List only entities whose sponsor is the group of this name"},
				"sponsor_state": {
					Type:        framework.TypeString,
					Description: "List only entities with a sponsor (accepted) or with a pending handover (pending)",
				},
				"ungoverned":  {Type: framework.TypeBool, Description: "List only ungoverned entities (no sponsor or no description)"},
				"governed_by": {Type: framework.TypeString, Description: `List only entities governed by this authority ("warden")`},
				"orphaned": {
					Type:        framework.TypeBool,
					Description: "List only entities claiming a native identity on an auth mount that no longer exists (disabled with force)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleEntityList,
					Summary:  "List the namespace's entities",
				},
			},
			HelpSynopsis:    "List namespace entities",
			HelpDescription: "List the entities of the namespace, optionally filtered by kind, state, sponsor or governance.",
		},
		{
			Pattern: "identity/entity/id/" + framework.GenericNameRegex("id"),
			Fields: map[string]*framework.FieldSchema{
				"id": {Type: framework.TypeString, Description: "ID of the entity", Required: true},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleEntityReadByID,
					Summary:  "Read an entity by ID",
				},
			},
			HelpSynopsis:    "Read an entity by ID",
			HelpDescription: "Read one entity of the namespace by its ID, which never changes.",
		},
		{
			Pattern: "identity/entity/" + framework.GenericNameRegex("entity") + "/alias/remove$",
			Fields: map[string]*framework.FieldSchema{
				"entity":         {Type: framework.TypeString, Description: "Name of the entity", Required: true},
				"mount":          boundMountField,
				"mount_accessor": accessorField,
				"name":           aliasField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleAliasRemove, Summary: "Release a native identity"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleAliasRemove, Summary: "Release a native identity"},
			},
			HelpSynopsis: "Release a native identity from an entity",
			HelpDescription: "The native identity is no longer claimed: it is unclaimed again. A retired entity keeps its " +
				"native identities; move them to another entity instead.",
		},
		{
			Pattern: "identity/entity/" + framework.GenericNameRegex("entity") + "/alias$",
			Fields: map[string]*framework.FieldSchema{
				"entity": {Type: framework.TypeString, Description: "Name of the entity", Required: true},
				"mount":  mountField,
				"name":   aliasField,
				"move": {
					Type:        framework.TypeBool,
					Description: "Take the native identity from the entity that claims it",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleAliasClaim, Summary: "Claim a native identity"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleAliasClaim, Summary: "Claim a native identity"},
			},
			HelpSynopsis: "Claim a native identity for an entity",
			HelpDescription: "Add a native identity to the entity. One another entity claims is refused unless move is set, " +
				"or that entity is retired; it is then taken from it. The mount must admit the entity's kind.",
		},
		{
			Pattern: "identity/entity/" + framework.GenericNameRegex("entity") + "/sponsor/remove$",
			Fields: map[string]*framework.FieldSchema{
				"entity": {Type: framework.TypeString, Description: "Name of the entity", Required: true},
				"pending": {
					Type:        framework.TypeBool,
					Description: "Cancel the pending handover instead of removing the sponsor",
				},
				"expected_hash": expectedHashField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleSponsorRemove, Summary: "Remove a sponsor"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSponsorRemove, Summary: "Remove a sponsor"},
			},
			HelpSynopsis: "Remove the sponsor of an entity, or cancel its pending handover",
			HelpDescription: "Without pending, the sponsor is removed and the entity is ungoverned; a pending handover stays " +
				"for a member to accept. With pending, the handover is cancelled.",
		},
		{
			Pattern: "identity/entity/" + framework.GenericNameRegex("entity") + "/sponsor$",
			Fields: map[string]*framework.FieldSchema{
				"entity": {Type: framework.TypeString, Description: "Name of the entity", Required: true},
				"group": {
					Type:        framework.TypeString,
					Description: "The virtual group of humans proposed as the sponsor, by name",
					Required:    true,
				},
				"namespace": {
					Type: framework.TypeString,
					Description: `The group's namespace, by path: this namespace (the default) or one of its ancestors ` +
						`("/" for the root namespace)`,
				},
				"expected_hash": expectedHashField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleSponsorPropose, Summary: "Propose a sponsor"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleSponsorPropose, Summary: "Propose a sponsor"},
			},
			HelpSynopsis: "Propose a sponsor for an entity",
			HelpDescription: "A sponsor is a virtual group of humans accountable for the entity. Proposed by a member of the " +
				"group, it is the sponsor at once; otherwise it is a pending handover, which a member accepts. Either way " +
				"the earlier sponsor stays until the new one is accepted.",
		},
		{
			Pattern: "identity/entity/" + framework.GenericNameRegex("entity") + "/state$",
			Fields: map[string]*framework.FieldSchema{
				"entity": {Type: framework.TypeString, Description: "Name of the entity", Required: true},
				"state": {
					Type:        framework.TypeString,
					Description: `active, suspended (reversible) or retired (final; the record becomes read-only)`,
					Required:    true,
				},
				"expected_hash": expectedHashField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleEntityState, Summary: "Change an entity's state"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleEntityState, Summary: "Change an entity's state"},
			},
			HelpSynopsis:    "Change the lifecycle state of an entity",
			HelpDescription: "Suspend an entity, make it active again, or retire it. Retirement is final.",
		},
		{
			Pattern: "identity/entity/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {Type: framework.TypeString, Description: "Name of the entity", Required: true},
				"kind": {
					Type:        framework.TypeString,
					Description: `Kind of entity: "agent" (the default; the only kind yet). Set on create and never changes.`,
				},
				"description": {
					Type:        framework.TypeString,
					Description: fmt.Sprintf("What the agent does (at most %d bytes). With a sponsor, it makes the entity governed.", logical.MaxEntityDescriptionBytes),
				},
				"profile": {
					Type:        framework.TypeMap,
					Description: "Descriptive data: purpose, runtime, publisher",
				},
				"metadata": {
					Type:        framework.TypeKVPairs,
					Description: fmt.Sprintf("Free-form string labels (at most %d keys)", logical.MaxRoleMetadataKeys),
				},
				"aliases": {
					Type: framework.TypeSlice,
					Description: "On create: the native identities the entity claims, each {\"mount\": \"auth/<path>/\", \"name\": \"...\"}. " +
						"Afterwards they change through the alias paths.",
				},
				"new_name": {
					Type:        framework.TypeString,
					Description: "On update: rename the entity. Its ID does not change.",
				},
				"governed_by": {
					Type:        framework.TypeString,
					Description: "Read-only: derived from the entity's fields. A write carrying it is refused.",
				},
				"expected_hash": {
					Type:        framework.TypeString,
					Description: "Apply the update or delete only if the entity still has this hash (from a read)",
				},
				"force": {
					Type: framework.TypeBool,
					Description: "On delete: delete a retired entity, whose native identities are then unclaimed again " +
						"(DELETE sys/identity/entity/<name>?force=true)",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleEntityCreate, Summary: "Create an entity"},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleEntityRead, Summary: "Read an entity"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleEntityUpdate, Summary: "Update an entity; fields left out keep their value"},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handleEntityDelete, Summary: "Delete an entity"},
			},
			HelpSynopsis: "Manage namespace entities",
			HelpDescription: "An entity is an agent of record: the native identities it presents through any auth mount, the " +
				"team accountable for it (its sponsor), and its lifecycle state. governed_by is \"warden\" once it has an " +
				"accepted sponsor and a description, and empty before.",
		},
		{
			Pattern: "identity/lookup$",
			Fields: map[string]*framework.FieldSchema{
				"mount":          boundMountField,
				"mount_accessor": accessorField,
				"name":           aliasField,
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.handleIdentityLookup, Summary: "Look up the entity of a native identity"},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleIdentityLookup, Summary: "Look up the entity of a native identity"},
			},
			HelpSynopsis:    "Look up the entity that claims a native identity",
			HelpDescription: "Answers which entity claims the native identity name presented through mount, if any.",
		},
	}
}

// resolveAliasMount returns the accessor and entity kind of the auth mount at
// path, relative to the namespace in ctx: the mount itself, not one above or
// below it, and one of the namespace's own.
func (c *Core) resolveAliasMount(ctx context.Context, path string) (accessor, kind string, err error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return "", "", ErrNamespaceNotInContext
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	notFound := logical.ErrBadRequestf("no auth mount at %q in this namespace", path)
	if !strings.HasPrefix(path, authRoutePrefix) {
		return "", "", notFound
	}
	entry, backend := c.router.MatchingMountEntryAndBackend(ctx, path)
	if entry == nil || entry.Class != mountClassAuth || entry.NamespaceID != ns.ID ||
		authRoutePrefix+entry.Path != path || entry.Tainted {
		return "", "", notFound
	}
	if fp, ok := backend.(logical.FactsProvider); ok {
		kind = fp.EntityKind()
	}
	return entry.Accessor, kind, nil
}

// aliasMountOf returns the accessor of the auth mount a request names: by
// path (mount), one of the namespace's own, or by accessor (mount_accessor),
// which also names a mount disabled since. Exactly one is required. An
// accessor of another namespace's mount matches none of this namespace's
// claims.
func (b *SystemBackend) aliasMountOf(ctx context.Context, d *framework.FieldData) (string, error) {
	path := d.Get("mount").(string)
	accessor := d.Get("mount_accessor").(string)
	switch {
	case path != "" && accessor != "":
		return "", logical.ErrBadRequest("mount and mount_accessor are exclusive")
	case path != "":
		accessor, _, err := b.core.resolveAliasMount(ctx, path)
		return accessor, err
	case accessor == "":
		return "", logical.ErrBadRequest("mount or mount_accessor is required")
	case !validAccessor(accessor):
		return "", logical.ErrBadRequestf("invalid mount_accessor %.64q", accessor)
	}
	return accessor, nil
}

// aliasMountPath renders the auth mount with accessor by its current path, or
// "" when no mount has it any more.
func (c *Core) aliasMountPath(accessor string) string {
	if entry := c.router.MatchingMountByAccessor(accessor); entry != nil && entry.Class == mountClassAuth {
		return authRoutePrefix + entry.Path
	}
	return ""
}

// mountPaths renders accessors as auth mount paths (aliasMountPath), and
// namespace IDs as namespace paths, for one response, resolving each once
// however many entities name it.
type mountPaths struct {
	core       *Core
	ctx        context.Context
	paths      map[string]string
	namespaces map[string]string
}

func (b *SystemBackend) mountPaths(ctx context.Context) *mountPaths {
	return &mountPaths{core: b.core, ctx: ctx}
}

func (p *mountPaths) of(accessor string) string {
	if accessor == "" {
		return ""
	}
	path, ok := p.paths[accessor]
	if !ok {
		path = p.core.aliasMountPath(accessor)
		if p.paths == nil {
			p.paths = make(map[string]string)
		}
		p.paths[accessor] = path
	}
	return path
}

// namespace renders the namespace with id by its path, "/" for the root
// namespace, or "" when no namespace has it any more.
func (p *mountPaths) namespace(id string) string {
	if id == namespace.RootNamespaceID {
		return "/"
	}
	path, ok := p.namespaces[id]
	if !ok {
		if ns, err := p.core.namespaceStore.GetNamespaceByAccessor(p.ctx, id); err == nil && ns != nil {
			path = ns.Path
		}
		if p.namespaces == nil {
			p.namespaces = make(map[string]string)
		}
		p.namespaces[id] = path
	}
	return path
}

// qualifiedName names a group or an entity with its namespace's path:
// "/billing-leads" in the root namespace, "team-a/billing-leads" in team-a.
func qualifiedName(nsPath, name string) string {
	if nsPath == "" || nsPath == "/" {
		return "/" + name
	}
	return nsPath + name
}

// sponsorToMap renders a sponsor or a pending handover for a response, nil
// when there is none. status is "accepted" or "pending".
func (p *mountPaths) sponsorToMap(sp *logical.EntitySponsor, status string) any {
	if sp == nil {
		return nil
	}
	actor := func(a logical.SponsorActor) any {
		if a == (logical.SponsorActor{}) {
			return nil
		}
		return map[string]any{
			"mount":          p.of(a.MountAccessor),
			"mount_accessor": a.MountAccessor,
			"alias":          a.Alias,
			"principal":      a.Principal,
		}
	}
	var acceptedAt any
	if !sp.AcceptedAt.IsZero() {
		acceptedAt = sp.AcceptedAt
	}
	return map[string]any{
		"type":        string(sp.Type),
		"namespace":   p.namespace(sp.Namespace),
		"group":       sp.Group,
		"group_id":    sp.GroupID,
		"added_by":    actor(sp.AddedBy),
		"added_at":    sp.AddedAt,
		"accepted_by": actor(sp.AcceptedBy),
		"accepted_at": acceptedAt,
		"status":      status,
	}
}

// entityToMap renders an entity for a response. Every key is present, so the
// shape is the same whichever fields the entity sets; a native identity whose
// mount no longer exists has an empty mount.
func (b *SystemBackend) entityToMap(e *logical.Entity, hash string, paths *mountPaths) map[string]any {
	metadata := e.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	profile := map[string]string{}
	if p := e.Profile; p != nil {
		for k, v := range map[string]string{"purpose": p.Purpose, "runtime": p.Runtime, "publisher": p.Publisher} {
			if v != "" {
				profile[k] = v
			}
		}
	}
	aliases := make([]map[string]any, len(e.Aliases))
	for i, a := range e.Aliases {
		aliases[i] = map[string]any{
			"mount":          paths.of(a.MountAccessor),
			"mount_accessor": a.MountAccessor,
			"name":           a.Name,
			"created_at":     a.CreatedAt,
		}
	}
	return map[string]any{
		"id":                e.ID,
		"name":              e.Name,
		"kind":              e.Kind,
		"description":       e.Description,
		"sponsor":           paths.sponsorToMap(e.Sponsor, "accepted"),
		"pending_sponsor":   paths.sponsorToMap(e.PendingSponsor, "pending"),
		"state":             string(e.State),
		"governed_by":       e.GovernedBy(),
		"ungoverned_reason": e.UngovernedReason(),
		"profile":           profile,
		"metadata":          metadata,
		"aliases":           aliases,
		"created_at":        e.CreatedAt,
		"updated_at":        e.UpdatedAt,
		"hash":              hash,
	}
}

// entityErrorResponse maps an identity store error to its response. A
// conflict names the mount by its path.
func (b *SystemBackend) entityErrorResponse(name string, err error) *logical.Response {
	var conflict *entityConflictError
	switch {
	case errors.As(err, &conflict):
		return logical.ErrorResponse(logical.ErrConflict(conflict.message(func(accessor string) string {
			if path := b.core.aliasMountPath(accessor); path != "" {
				return path
			}
			return accessor
		})))
	case errors.Is(err, ErrEntityNotFound):
		return logical.ErrorResponse(logical.ErrNotFoundf("entity %q not found", name))
	case errors.Is(err, ErrEntityAlreadyExists):
		return logical.ErrorResponse(logical.ErrConflictf("entity %q already exists", name))
	case errors.Is(err, ErrEntityChanged):
		return logical.ErrorResponse(logical.ErrConflictf(
			"entity %q changed since it was read (expected_hash no longer matches); read it again and retry", name))
	case errors.Is(err, ErrEntityRetired):
		return logical.ErrorResponse(logical.ErrConflictf(
			"entity %q is retired: its record is read-only, and its native identities can only be moved to "+
				"another entity; a delete needs force", name))
	case errors.Is(err, ErrAliasNotFound):
		return logical.ErrorResponse(logical.ErrNotFound("native identity not claimed"))
	case errors.Is(err, ErrSponsorNotFound):
		return logical.ErrorResponse(logical.ErrNotFoundf("entity %q has no such sponsor", name))
	case errors.Is(err, ErrSponsorGroupNotFound):
		return logical.ErrorResponse(logical.ErrBadRequest(
			"the sponsor group no longer exists (deleted, or deleted and created again); propose it again"))
	case errors.Is(err, ErrSponsorGroupNotVirtual):
		return logical.ErrorResponse(logical.ErrBadRequest(errStaticSponsor))
	case errors.Is(err, ErrSponsorChanged):
		return logical.ErrorResponse(logical.ErrConflictf(
			"the sponsor of entity %q changed since it was read; read it again and retry", name))
	case errors.Is(err, ErrTooManyEntities):
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error()))
	case errors.Is(err, ErrIdentityStoreNotLoaded):
		return logical.ErrorResponse(logical.ErrServiceUnavailable(err.Error()))
	}
	return logical.ErrorResponse(err)
}

// parseProfile converts the profile field of a write.
func parseProfile(raw map[string]any) (*logical.AgentProfile, error) {
	p := &logical.AgentProfile{}
	for k, v := range raw {
		s, ok := v.(string)
		if !ok {
			return nil, logical.ErrBadRequestf("profile.%s must be a string", k)
		}
		switch k {
		case "purpose":
			p.Purpose = s
		case "runtime":
			p.Runtime = s
		case "publisher":
			p.Publisher = s
		default:
			return nil, logical.ErrBadRequestf("unknown profile field %q: one of purpose, runtime, publisher", k)
		}
	}
	return p, nil
}

// errStaticSponsor refuses a sponsor group that is not virtual.
const errStaticSponsor = "a static group's members are agents; an agent cannot sponsor"

// mergeEntityFields writes onto e every descriptive field present in the
// request. The sponsor and the state are refused, whatever their value: each
// changes through a path of its own. They are left out of the schema and read
// from the raw body, so a value of any type is refused the same way rather
// than failing field validation first.
func mergeEntityFields(e *logical.Entity, d *framework.FieldData) error {
	if _, ok := d.GetOk("governed_by"); ok {
		return logical.ErrBadRequest("governed_by is derived and cannot be written")
	}
	for _, k := range []string{"sponsor", "sponsors"} {
		if _, ok := d.Raw[k]; ok {
			return logical.ErrBadRequest("the sponsor is proposed through sys/identity/entity/<name>/sponsor")
		}
	}
	if _, ok := d.Raw["state"]; ok {
		return logical.ErrBadRequest("state changes through sys/identity/entity/<name>/state")
	}
	if v, ok := d.GetOk("kind"); ok {
		e.Kind = v.(string)
	}
	if v, ok := d.GetOk("description"); ok {
		e.Description = v.(string)
	}
	if v, ok := d.GetOk("profile"); ok {
		p, err := parseProfile(v.(map[string]any))
		if err != nil {
			return err
		}
		e.Profile = p
	}
	if v, ok := d.GetOk("metadata"); ok {
		e.Metadata = v.(map[string]string)
	}
	return nil
}

// handleEntityCreate handles POST sys/identity/entity/<name>.
func (b *SystemBackend) handleEntityCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if d.Get("expected_hash").(string) != "" {
		return logical.ErrorResponse(logical.ErrBadRequest(
			"expected_hash applies to an update or a delete; a create has no earlier version")), nil
	}
	if d.Get("new_name").(string) != "" {
		return logical.ErrorResponse(logical.ErrBadRequest("new_name applies to an update")), nil
	}
	e := &logical.Entity{Name: name}
	if err := mergeEntityFields(e, d); err != nil {
		return logical.ErrorResponse(err), nil
	}
	if e.Kind == "" {
		e.Kind = logical.EntityKindAgent
	}
	if raw, ok := d.GetOk("aliases"); ok {
		for i, item := range raw.([]any) {
			m, ok := item.(map[string]any)
			if !ok {
				return logical.ErrorResponse(logical.ErrBadRequestf(
					"aliases[%d]: must be an object {\"mount\": ..., \"name\": ...}, got %T", i, item)), nil
			}
			mount, _ := m["mount"].(string)
			alias, _ := m["name"].(string)
			accessor, err := b.claimableMount(ctx, mount, e.Kind)
			if err != nil {
				return logical.ErrorResponse(fmt.Errorf("aliases[%d]: %w", i, err)), nil
			}
			e.Aliases = append(e.Aliases, logical.EntityAlias{MountAccessor: accessor, Name: alias})
		}
	}
	if err := b.core.identityStore.CreateEntity(ctx, e); err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	return b.respondCreated(b.entityToMap(e, e.Hash(), b.mountPaths(ctx))), nil
}

// claimableMount resolves the auth mount at path and checks that it admits
// entities of kind: a native identity is claimed only by an entity of the kind
// its mount admits.
func (b *SystemBackend) claimableMount(ctx context.Context, path, kind string) (string, error) {
	if path == "" {
		return "", logical.ErrBadRequest("mount is required")
	}
	accessor, mountKind, err := b.core.resolveAliasMount(ctx, path)
	if err != nil {
		return "", err
	}
	if mountKind != "" && mountKind != kind {
		return "", logical.ErrBadRequestf("auth mount %q admits %s entities; this entity is a %s", path, mountKind, kind)
	}
	return accessor, nil
}

// handleEntityRead handles GET sys/identity/entity/<name>.
func (b *SystemBackend) handleEntityRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	e, hash, err := b.core.identityStore.GetEntity(ctx, name)
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	return b.respondSuccess(b.entityToMap(e, hash, b.mountPaths(ctx))), nil
}

// handleEntityReadByID handles GET sys/identity/entity/id/<id>.
func (b *SystemBackend) handleEntityReadByID(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	e, hash, err := b.core.identityStore.GetEntityByID(ctx, id)
	if err != nil {
		return b.entityErrorResponse(id, err), nil
	}
	return b.respondSuccess(b.entityToMap(e, hash, b.mountPaths(ctx))), nil
}

// handleEntityUpdate handles PUT sys/identity/entity/<name>. A field present
// in the request replaces the stored value; a field left out keeps it.
// new_name renames the entity. The aliases change only through the alias
// paths. Without expected_hash a write that loses to a concurrent one is
// merged onto the new version and tried once more.
func (b *SystemBackend) handleEntityUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	expected := d.Get("expected_hash").(string)
	if _, ok := d.GetOk("aliases"); ok {
		return logical.ErrorResponse(logical.ErrBadRequest(
			"aliases change through sys/identity/entity/<name>/alias and .../alias/remove")), nil
	}
	for attempt := 1; ; attempt++ {
		e, hash, err := b.core.identityStore.GetEntity(ctx, name)
		if err != nil {
			return b.entityErrorResponse(name, err), nil
		}
		if expected != "" && expected != hash {
			return b.entityErrorResponse(name, ErrEntityChanged), nil
		}
		if err := mergeEntityFields(e, d); err != nil {
			return logical.ErrorResponse(err), nil
		}
		if v := d.Get("new_name").(string); v != "" {
			e.Name = v
		}
		err = b.core.identityStore.UpdateEntity(ctx, name, e, hash)
		if errors.Is(err, ErrEntityChanged) && expected == "" && attempt < 2 {
			continue
		}
		if err != nil {
			return b.entityErrorResponse(name, err), nil
		}
		return b.respondSuccess(b.entityToMap(e, e.Hash(), b.mountPaths(ctx))), nil
	}
}

// handleEntityDelete handles DELETE sys/identity/entity/<name>, conditional on
// expected_hash (a query parameter) when set; a retired entity needs force.
func (b *SystemBackend) handleEntityDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	forced, err := b.core.identityStore.DeleteEntity(ctx, name, d.Get("expected_hash").(string), d.Get("force").(bool))
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	data := map[string]any{
		"name":    name,
		"message": fmt.Sprintf("Successfully deleted entity %s", name),
	}
	if forced != "" {
		appendWarnings(data, forced)
	}
	return b.respondSuccess(data), nil
}

// handleEntityList handles LIST sys/identity/entity. It returns the names
// under "keys" and the entities themselves under "entities", sorted by name.
func (b *SystemBackend) handleEntityList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	paths := b.mountPaths(ctx)
	f := EntityFilter{
		Kind:       d.Get("kind").(string),
		Sponsor:    d.Get("sponsor").(string),
		Ungoverned: d.Get("ungoverned").(bool),
		GovernedBy: d.Get("governed_by").(string),
	}
	switch st := SponsorState(d.Get("sponsor_state").(string)); st {
	case "", SponsorStateAccepted, SponsorStatePending:
		f.SponsorState = st
	default:
		return logical.ErrorResponse(logical.ErrBadRequestf("unknown sponsor_state %q: %q or %q",
			st, SponsorStateAccepted, SponsorStatePending)), nil
	}
	if d.Get("orphaned").(bool) {
		f.MountGone = func(accessor string) bool { return paths.of(accessor) == "" }
	}
	if v := d.Get("state").(string); v != "" {
		st, err := logical.ParseEntityState(v)
		if err != nil {
			return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
		}
		f.State = st
	}
	entities, hashes, err := b.core.identityStore.ListEntities(ctx, f)
	if err != nil {
		return b.entityErrorResponse("", err), nil
	}
	keys := make([]string, len(entities))
	items := make([]map[string]any, len(entities))
	for i, e := range entities {
		keys[i] = e.Name
		items[i] = b.entityToMap(e, hashes[i], paths)
	}
	return b.respondSuccess(map[string]any{"keys": keys, "entities": items}), nil
}

// handleAliasClaim handles POST sys/identity/entity/<entity>/alias.
func (b *SystemBackend) handleAliasClaim(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	e, _, err := b.core.identityStore.GetEntity(ctx, name)
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	mount := d.Get("mount").(string)
	accessor, err := b.claimableMount(ctx, mount, e.Kind)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	alias := d.Get("name").(string)
	from, err := b.core.identityStore.ClaimAlias(ctx, name, accessor, alias, d.Get("move").(bool))
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	data := map[string]any{
		"entity":         name,
		"mount":          b.core.aliasMountPath(accessor),
		"mount_accessor": accessor,
		"name":           alias,
	}
	if from != "" {
		data["moved_from"] = from
	}
	return b.respondSuccess(data), nil
}

// handleAliasRemove handles POST sys/identity/entity/<entity>/alias/remove.
func (b *SystemBackend) handleAliasRemove(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	accessor, err := b.aliasMountOf(ctx, d)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	if err := b.core.identityStore.RemoveAlias(ctx, name, accessor, d.Get("name").(string)); err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	return b.respondSuccess(map[string]any{
		"entity":  name,
		"message": "Successfully released the native identity",
	}), nil
}

// handleIdentityLookup handles POST sys/identity/lookup.
func (b *SystemBackend) handleIdentityLookup(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	accessor, err := b.aliasMountOf(ctx, d)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	e, err := b.core.identityStore.LookupAlias(ctx, accessor, d.Get("name").(string))
	if err != nil {
		return b.entityErrorResponse("", err), nil
	}
	return b.respondSuccess(map[string]any{
		"entity":      e.Name,
		"entity_id":   e.ID,
		"kind":        e.Kind,
		"state":       string(e.State),
		"governed_by": e.GovernedBy(),
	}), nil
}

// sponsorNamespace resolves the namespace a sponsor proposal names by path:
// the request's own namespace when path is empty, or one of its ancestors
// ("/" is the root namespace). A sibling or a descendant is refused: a sponsor
// group is one the entity's namespace inherits.
func (c *Core) sponsorNamespace(ctx context.Context, path string) (*namespace.Namespace, error) {
	reqNS, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, ErrNamespaceNotInContext
	}
	if path == "" {
		return reqNS, nil
	}
	p := namespace.Canonicalize(path)
	switch {
	case p == reqNS.Path:
		return reqNS, nil
	case p == "":
		return namespace.RootNamespace, nil
	case !strings.HasPrefix(reqNS.Path, p):
		return nil, logical.ErrBadRequestf("namespace %q is neither this namespace nor one of its ancestors", path)
	}
	ns, err := c.namespaceStore.GetNamespaceByPath(namespace.ContextWithNamespace(ctx, namespace.RootNamespace), p)
	if err != nil {
		return nil, err
	}
	if ns == nil {
		return nil, logical.ErrBadRequestf("namespace %q not found", path)
	}
	return ns, nil
}

// sponsorGroupWarnings says why the group g of namespace ns may never act for
// the entities it sponsors: no auth mount of its namespace admits humans, or
// every rule's "kind" selector excludes them (nobody could ever accept it or
// act for it), or a rule trusts a mount that admits agents (only humans act
// for a sponsor). Each is a warning, never a refusal: mounts and rules change
// after a proposal, and who may act is checked when someone acts.
func (c *Core) sponsorGroupWarnings(ctx context.Context, ns *namespace.Namespace, g *logical.Group) []string {
	mounts := c.namespaceAuthMountFacts(namespace.ContextWithNamespace(ctx, ns))
	var warnings []string
	if !slices.ContainsFunc(mounts, func(m authMountFacts) bool { return m.kind == logical.EntityKindHuman }) {
		warnings = append(warnings, fmt.Sprintf(
			"no auth mount of namespace %s admits humans: nobody can accept or act for this sponsor until one is enabled there",
			qualifiedName(ns.Path, "")))
	}
	if !slices.ContainsFunc(g.Rules, func(r logical.GroupRule) bool { return ruleAdmitsKind(r, logical.EntityKindHuman) }) {
		warnings = append(warnings, fmt.Sprintf(
			`group %q: no rule can admit a human (each rule's "kind" selector excludes "human"); nobody can accept or act for this sponsor`,
			g.Name))
	}
	for i, rule := range g.Rules {
		for _, m := range mounts {
			if m.kind == logical.EntityKindAgent && ruleTrustsMount(rule, m.path) {
				warnings = append(warnings, fmt.Sprintf(
					"group %q: rules[%d] trusts %s, which admits agents; only humans act for a sponsor", g.Name, i, m.path))
			}
		}
	}
	return warnings
}

// handleSponsorPropose handles POST sys/identity/entity/<entity>/sponsor. The
// group must be a virtual group of this namespace or of an ancestor. A writer
// who is a member of it makes it the sponsor at once; anyone else proposes a
// handover, which a member accepts. Root, a member of no group, always
// proposes.
func (b *SystemBackend) handleSponsorPropose(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	groupName := d.Get("group").(string)
	if groupName == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("group is required")), nil
	}
	te := req.TokenEntry()
	if te == nil {
		return logical.ErrorResponse(logical.ErrForbidden("a sponsor is proposed by a caller with a token")), nil
	}
	ns, err := b.core.sponsorNamespace(ctx, d.Get("namespace").(string))
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	qualified := qualifiedName(ns.Path, groupName)
	g := b.core.grantIndex(ns.ID).groupsByName[groupName]
	switch {
	case g == nil:
		return logical.ErrorResponse(logical.ErrBadRequestf("group %s not found", qualified)), nil
	case g.Type != logical.GroupTypeVirtual:
		return logical.ErrorResponse(logical.ErrBadRequest(errStaticSponsor)), nil
	}
	sp := &logical.EntitySponsor{
		Type:      logical.SponsorTypeGroup,
		Namespace: ns.ID,
		GroupID:   g.ID,
		Group:     g.Name,
		AddedBy:   sponsorActor(te),
		AddedAt:   time.Now().UTC(),
	}
	groups, issuingNS, human := requestMembership(req)
	accepted := human && b.core.callerMatches(sp, groups, issuingNS)
	outcome, err := b.core.identityStore.ProposeSponsor(ctx, name, sp, accepted, nil, d.Get("expected_hash").(string))
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	e, hash, err := b.core.identityStore.GetEntity(ctx, name)
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	data := b.entityToMap(e, hash, b.mountPaths(ctx))
	if outcome == ProposePending {
		appendWarnings(data, fmt.Sprintf("handover to %s is pending: a member must accept it", qualified))
	}
	appendWarnings(data, b.core.sponsorGroupWarnings(ctx, ns, g.Group)...)
	return b.respondSuccess(data), nil
}

// handleSponsorRemove handles POST sys/identity/entity/<entity>/sponsor/remove:
// it removes the sponsor, leaving the entity ungoverned, or with pending
// cancels the pending handover.
func (b *SystemBackend) handleSponsorRemove(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	expected := d.Get("expected_hash").(string)
	pending := d.Get("pending").(bool)
	e, _, err := b.core.identityStore.GetEntity(ctx, name)
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	var warning string
	switch {
	case pending && e.PendingSponsor == nil:
		return logical.ErrorResponse(logical.ErrNotFoundf("entity %q has no pending sponsor handover", name)), nil
	case pending:
		err = b.core.identityStore.CancelPending(ctx, name, nil, expected)
	case e.Sponsor == nil:
		return logical.ErrorResponse(logical.ErrNotFoundf("entity %q has no sponsor", name)), nil
	default:
		err = b.core.identityStore.ClearSponsor(ctx, name, expected)
		warning = "entity is now ungoverned: it has no sponsor"
	}
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	e, hash, err := b.core.identityStore.GetEntity(ctx, name)
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	data := b.entityToMap(e, hash, b.mountPaths(ctx))
	if warning != "" {
		appendWarnings(data, warning)
	}
	return b.respondSuccess(data), nil
}

// handleEntityState handles POST sys/identity/entity/<entity>/state.
func (b *SystemBackend) handleEntityState(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("entity").(string)
	v := d.Get("state").(string)
	// An empty state would read as active and lift a suspension.
	if v == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("state must be active, suspended or retired")), nil
	}
	st, err := logical.ParseEntityState(v)
	if err != nil {
		return logical.ErrorResponse(logical.ErrBadRequest(err.Error())), nil
	}
	if err := b.core.identityStore.SetEntityState(ctx, name, st, nil, d.Get("expected_hash").(string)); err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	e, hash, err := b.core.identityStore.GetEntity(ctx, name)
	if err != nil {
		return b.entityErrorResponse(name, err), nil
	}
	return b.respondSuccess(b.entityToMap(e, hash, b.mountPaths(ctx))), nil
}
