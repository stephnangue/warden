package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/internal/namespace"
	"github.com/stephnangue/warden/logger"
	"github.com/stephnangue/warden/logical"
)

// pathSkills returns the paths for skill registry operations.
//
// Skills are a single global set shared across all namespaces. Reads are
// open to any authenticated caller in any namespace; mutations
// (create/update/delete) are restricted to the root namespace, enforced
// inside the handlers (see requireRootNamespace).
func (b *SystemBackend) pathSkills() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "skills/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "The skill name (unique slug)",
					Required:    true,
				},
				"description": {
					Type:        framework.TypeString,
					Description: "Human-friendly one-line summary",
				},
				"category": {
					Type:        framework.TypeString,
					Description: "Skill category: agent-flow, shared, provider-guide, troubleshooting, custom",
				},
				"requires": {
					Type:        framework.TypeStringSlice,
					Description: "Names of other skills this one depends on",
				},
				"upstream": {
					Type:        framework.TypeString,
					Description: "Reference to an upstream system, when applicable",
				},
				"provider": {
					Type:        framework.TypeString,
					Description: "Provider type this skill describes (required for provider-guide category)",
				},
				"body": {
					Type:        framework.TypeString,
					Description: "Markdown body — the agent-facing recipe",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleSkillCreate,
					Summary:  "Create a new skill (root namespace only)",
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleSkillRead,
					Summary:  "Read a skill record",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleSkillUpdate,
					Summary:  "Update an existing skill (root namespace only)",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleSkillDelete,
					Summary:  "Delete a skill (root namespace only)",
				},
			},
			HelpSynopsis:    "Manage agent skills",
			HelpDescription: "Create, read, update, and delete entries in the global agent skill registry. Reads are open to any namespace; writes are restricted to the root namespace.",
		},
		{
			Pattern: "skills/?$",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleSkillList,
					Summary:  "List all skills",
				},
			},
			HelpSynopsis:    "List agent skills",
			HelpDescription: "List every skill in the global agent skill registry.",
		},
	}
}

// requireRootNamespace returns nil if the request is scoped to the root
// namespace, otherwise a 403 CodedError. Used to gate the write
// operations on /v1/sys/skills/*.
func requireRootNamespace(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return logical.ErrForbidden("namespace required")
	}
	if ns.ID != namespace.RootNamespaceID {
		return logical.ErrForbidden("skill mutations are restricted to the root namespace")
	}
	return nil
}

// skillToMap converts a Skill record into the JSON-serializable map used
// in API responses. When omitBody is true, the body is excluded — used
// by LIST responses to keep payloads small.
func skillToMap(s *Skill, omitBody bool) map[string]any {
	out := map[string]any{
		"name":        s.Name,
		"description": s.Description,
		"category":    s.Category,
		"origin":      s.Origin,
		"version":     s.Version,
		"created_at":  s.CreatedAt,
		"updated_at":  s.UpdatedAt,
	}
	if len(s.Requires) > 0 {
		out["requires"] = s.Requires
	}
	if s.Upstream != "" {
		out["upstream"] = s.Upstream
	}
	if s.Provider != "" {
		out["provider"] = s.Provider
	}
	if !omitBody {
		out["body"] = s.Body
	}
	return out
}

// skillFromFields builds a Skill record from incoming request fields.
// Used by CREATE; UPDATE re-uses the same shape via merge semantics.
func skillFromFields(d *framework.FieldData) *Skill {
	skill := &Skill{
		Name:        d.Get("name").(string),
		Description: d.Get("description").(string),
		Category:    d.Get("category").(string),
		Upstream:    d.Get("upstream").(string),
		Provider:    d.Get("provider").(string),
		Body:        d.Get("body").(string),
	}
	if req, ok := d.GetOk("requires"); ok {
		skill.Requires = req.([]string)
	}
	return skill
}

// handleSkillCreate handles POST /sys/skills/{name}.
func (b *SystemBackend) handleSkillCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := requireRootNamespace(ctx); err != nil {
		return logical.ErrorResponse(err), nil
	}
	if b.core.skillStore == nil {
		return logical.ErrorResponse(logical.ErrInternal("skill store not initialized")), nil
	}

	skill := skillFromFields(d)

	if err := b.core.skillStore.Create(ctx, skill); err != nil {
		if errors.Is(err, ErrSkillAlreadyExists) {
			return logical.ErrorResponse(logical.ErrConflictf("skill %q already exists", skill.Name)), nil
		}
		return logical.ErrorResponse(err), nil
	}

	b.logger.Info("created skill",
		logger.String("name", skill.Name),
		logger.String("category", skill.Category),
	)
	return b.respondCreated(skillToMap(skill, false)), nil
}

// handleSkillRead handles GET /sys/skills/{name}.
func (b *SystemBackend) handleSkillRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if b.core.skillStore == nil {
		return logical.ErrorResponse(logical.ErrInternal("skill store not initialized")), nil
	}
	name := d.Get("name").(string)

	skill, err := b.core.skillStore.Get(ctx, name)
	if err != nil {
		if errors.Is(err, ErrSkillNotFound) {
			return logical.ErrorResponse(logical.ErrNotFoundf("skill %q not found", name)), nil
		}
		return logical.ErrorResponse(err), nil
	}

	return b.respondSuccess(skillToMap(skill, false)), nil
}

// handleSkillUpdate handles PUT /sys/skills/{name}. Empty fields in the
// payload are treated as "don't change"; non-empty values overwrite.
// CreatedAt, Origin, Name, and Version are managed by the store.
func (b *SystemBackend) handleSkillUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := requireRootNamespace(ctx); err != nil {
		return logical.ErrorResponse(err), nil
	}
	if b.core.skillStore == nil {
		return logical.ErrorResponse(logical.ErrInternal("skill store not initialized")), nil
	}

	name := d.Get("name").(string)
	patch := skillFromFields(d)
	patch.Name = "" // never patch the primary key

	updated, err := b.core.skillStore.Update(ctx, name, patch)
	if err != nil {
		if errors.Is(err, ErrSkillNotFound) {
			return logical.ErrorResponse(logical.ErrNotFoundf("skill %q not found", name)), nil
		}
		return logical.ErrorResponse(err), nil
	}

	b.logger.Info("updated skill",
		logger.String("name", updated.Name),
		logger.Int("version", updated.Version),
	)
	return b.respondSuccess(skillToMap(updated, false)), nil
}

// handleSkillDelete handles DELETE /sys/skills/{name}.
func (b *SystemBackend) handleSkillDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if err := requireRootNamespace(ctx); err != nil {
		return logical.ErrorResponse(err), nil
	}
	if b.core.skillStore == nil {
		return logical.ErrorResponse(logical.ErrInternal("skill store not initialized")), nil
	}

	name := d.Get("name").(string)

	if err := b.core.skillStore.Delete(ctx, name); err != nil {
		if errors.Is(err, ErrSkillNotFound) {
			return logical.ErrorResponse(logical.ErrNotFoundf("skill %q not found", name)), nil
		}
		return logical.ErrorResponse(err), nil
	}

	b.logger.Info("deleted skill", logger.String("name", name))
	return b.respondSuccess(map[string]any{
		"message": fmt.Sprintf("Successfully deleted skill %s", name),
	}), nil
}

// handleSkillList handles GET /sys/skills.
//
// Returns short-form records (body omitted) to keep payloads small.
// Agents that need full content fetch each name individually via READ.
func (b *SystemBackend) handleSkillList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if b.core.skillStore == nil {
		return logical.ErrorResponse(logical.ErrInternal("skill store not initialized")), nil
	}

	skills, err := b.core.skillStore.List(ctx)
	if err != nil {
		return logical.ErrorResponse(err), nil
	}

	items := make([]map[string]any, 0, len(skills))
	for _, s := range skills {
		items = append(items, skillToMap(s, true))
	}

	return b.respondSuccess(map[string]any{
		"skills": items,
	}), nil
}
