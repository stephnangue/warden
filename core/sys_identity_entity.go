package core

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	return []*framework.Path{
		{
			Pattern: "identity/entity/?$",
			Fields: map[string]*framework.FieldSchema{
				"kind":        {Type: framework.TypeString, Description: "List only entities of this kind"},
				"state":       {Type: framework.TypeString, Description: "List only entities in this state"},
				"sponsor":     {Type: framework.TypeString, Description: "List only entities this sponsor is accountable for"},
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
				"sponsors": {
					Type:        framework.TypeCommaStringSlice,
					Description: fmt.Sprintf("The humans accountable for the agent, as UPNs or email addresses (at most %d)", logical.MaxEntitySponsors),
				},
				"state": {
					Type:        framework.TypeString,
					Description: `active (default), suspended (the reversible kill switch) or retired (final; the record becomes read-only)`,
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
				"humans accountable for it, and its lifecycle state. governed_by is \"warden\" once it has a sponsor and " +
				"a description, and empty before.",
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

// mountPaths renders accessors as auth mount paths (aliasMountPath) for one
// response, resolving each accessor once however many entities claim on it.
type mountPaths struct {
	core  *Core
	paths map[string]string
}

func (b *SystemBackend) mountPaths() *mountPaths { return &mountPaths{core: b.core} }

func (p *mountPaths) of(accessor string) string {
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

// entityToMap renders an entity for a response. Every key is present, so the
// shape is the same whichever fields the entity sets; a native identity whose
// mount no longer exists has an empty mount.
func (b *SystemBackend) entityToMap(e *logical.Entity, hash string, paths *mountPaths) map[string]any {
	sponsors := e.Sponsors
	if sponsors == nil {
		sponsors = []string{}
	}
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
		"sponsors":          sponsors,
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

// entityErrorResponse maps an identity store error to its response.
func entityErrorResponse(name string, err error) *logical.Response {
	switch {
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

// mergeEntityFields writes onto e every governance field present in the
// request.
func mergeEntityFields(e *logical.Entity, d *framework.FieldData) error {
	if _, ok := d.GetOk("governed_by"); ok {
		return logical.ErrBadRequest("governed_by is derived and cannot be written")
	}
	if v, ok := d.GetOk("kind"); ok {
		e.Kind = v.(string)
	}
	if v, ok := d.GetOk("description"); ok {
		e.Description = v.(string)
	}
	if v, ok := d.GetOk("sponsors"); ok {
		e.Sponsors = v.([]string)
	}
	if v, ok := d.GetOk("state"); ok {
		// An empty state would read as active and lift a suspension; a write
		// that sends state names one.
		if v.(string) == "" {
			return logical.ErrBadRequest("state must be active, suspended or retired")
		}
		st, err := logical.ParseEntityState(v.(string))
		if err != nil {
			return logical.ErrBadRequest(err.Error())
		}
		e.State = st
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
		return entityErrorResponse(name, err), nil
	}
	return b.respondCreated(b.entityToMap(e, e.Hash(), b.mountPaths())), nil
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
		return entityErrorResponse(name, err), nil
	}
	return b.respondSuccess(b.entityToMap(e, hash, b.mountPaths())), nil
}

// handleEntityReadByID handles GET sys/identity/entity/id/<id>.
func (b *SystemBackend) handleEntityReadByID(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id := d.Get("id").(string)
	e, hash, err := b.core.identityStore.GetEntityByID(ctx, id)
	if err != nil {
		return entityErrorResponse(id, err), nil
	}
	return b.respondSuccess(b.entityToMap(e, hash, b.mountPaths())), nil
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
			return entityErrorResponse(name, err), nil
		}
		if expected != "" && expected != hash {
			return entityErrorResponse(name, ErrEntityChanged), nil
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
			return entityErrorResponse(name, err), nil
		}
		return b.respondSuccess(b.entityToMap(e, e.Hash(), b.mountPaths())), nil
	}
}

// handleEntityDelete handles DELETE sys/identity/entity/<name>, conditional on
// expected_hash (a query parameter) when set; a retired entity needs force.
func (b *SystemBackend) handleEntityDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	err := b.core.identityStore.DeleteEntity(ctx, name, d.Get("expected_hash").(string), d.Get("force").(bool))
	if err != nil {
		return entityErrorResponse(name, err), nil
	}
	return b.respondSuccess(map[string]any{
		"name":    name,
		"message": fmt.Sprintf("Successfully deleted entity %s", name),
	}), nil
}

// handleEntityList handles LIST sys/identity/entity. It returns the names
// under "keys" and the entities themselves under "entities", sorted by name.
func (b *SystemBackend) handleEntityList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	paths := b.mountPaths()
	f := EntityFilter{
		Kind:       d.Get("kind").(string),
		Sponsor:    d.Get("sponsor").(string),
		Ungoverned: d.Get("ungoverned").(bool),
		GovernedBy: d.Get("governed_by").(string),
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
		return entityErrorResponse("", err), nil
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
		return entityErrorResponse(name, err), nil
	}
	mount := d.Get("mount").(string)
	accessor, err := b.claimableMount(ctx, mount, e.Kind)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}
	alias := d.Get("name").(string)
	from, err := b.core.identityStore.ClaimAlias(ctx, name, accessor, alias, d.Get("move").(bool))
	if err != nil {
		return entityErrorResponse(name, err), nil
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
		return entityErrorResponse(name, err), nil
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
		return entityErrorResponse("", err), nil
	}
	return b.respondSuccess(map[string]any{
		"entity":      e.Name,
		"entity_id":   e.ID,
		"kind":        e.Kind,
		"state":       string(e.State),
		"governed_by": e.GovernedBy(),
	}), nil
}
