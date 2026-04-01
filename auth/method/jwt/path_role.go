package jwt

import (
	"context"
	"fmt"
	"net/http"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

const rolePrefix = "role/"

// pathRole returns the role CRUD path definition
func (b *jwtAuthBackend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
			"bound_audiences": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of audiences that are valid for this role",
			},
			"bound_subject": {
				Type:        framework.TypeString,
				Description: "Subject claim that must match for this role",
			},
			"bound_claims": {
				Type:        framework.TypeMap,
				Description: "Map of claims that must match for this role",
			},
			"bound_uri_patterns": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Segment-aware URI patterns to match against uri_claim (e.g. spiffe://+/dept/*, spiffe://*)",
			},
			"uri_claim": {
				Type:        framework.TypeString,
				Description: "JWT claim to validate against bound_uri_patterns (default: sub)",
			},
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of policies to assign to tokens",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token TTL",
				Default:     3600,
			},
			"user_claim": {
				Type:        framework.TypeString,
				Description: "Claim to use as the principal identity",
				Default:     "sub",
			},
			"cred_spec_name": {
				Type:        framework.TypeString,
				Description: "Credential spec name",
			},
			"groups_claim": {
				Type:        framework.TypeString,
				Description: "Override global groups_claim for this role",
			},
			"group_policy_prefix": {
				Type:        framework.TypeString,
				Description: "Override global group_policy_prefix for this role",
			},
			"max_age": {
				Type:        framework.TypeString,
				Description: "Maximum elapsed time since JWT was issued (iat). Rejects JWTs older than this. Example: 30m, 1h",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleRoleCreate,
				Summary:  "Create a new role",
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleRoleRead,
				Summary:  "Read role configuration",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleRoleUpdate,
				Summary:  "Update role configuration",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.handleRoleDelete,
				Summary:  "Delete a role",
			},
		},
		HelpSynopsis:    "Manage JWT auth roles",
		HelpDescription: "Create, read, update, and delete roles for JWT authentication.",
	}
}

// pathRoleList returns the role list path definition
func (b *jwtAuthBackend) pathRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleRoleList,
				Summary:  "List all roles",
			},
		},
		HelpSynopsis:    "List JWT auth roles",
		HelpDescription: "List all configured roles for JWT authentication.",
	}
}

// handleRoleCreate creates a new role
func (b *jwtAuthBackend) handleRoleCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Check if role already exists
	existing, err := b.getRole(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if existing != nil {
		return logical.ErrorResponse(logical.ErrConflictf("role %q already exists", name)), nil
	}

	// Build role from request data
	role := b.buildRoleFromFieldData(name, d)

	// Validate and set defaults
	if err := b.validateRole(role); err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Persist role
	if err := b.setRole(ctx, role); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	return &logical.Response{
		StatusCode: http.StatusCreated,
		Data: map[string]any{
			"name":    role.Name,
			"message": fmt.Sprintf("Successfully created role %s", name),
		},
	}, nil
}

// handleRoleRead reads a role configuration
func (b *jwtAuthBackend) handleRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.getRole(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if role == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("role %q not found", name)), nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"name":                role.Name,
			"bound_audiences":     role.BoundAudiences,
			"bound_subject":       role.BoundSubject,
			"bound_claims":        role.BoundClaims,
			"bound_uri_patterns":  role.BoundURIPatterns,
			"uri_claim":           role.URIClaim,
			"token_policies":      role.TokenPolicies,
			"token_ttl":           role.TokenTTL,
			"user_claim":          role.UserClaim,
			"cred_spec_name":      role.CredSpecName,
			"groups_claim":        role.GroupsClaim,
			"group_policy_prefix": role.GroupPolicyPrefix,
			"max_age":             role.MaxAge,
		},
	}, nil
}

// handleRoleUpdate updates an existing role or creates it if it doesn't exist (upsert pattern).
func (b *jwtAuthBackend) handleRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.getRole(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	isCreate := role == nil
	if isCreate {
		role = b.buildRoleFromFieldData(name, d)
	} else {
		// Update existing role — only update fields that are provided
		if v, ok := d.GetOk("bound_audiences"); ok {
			role.BoundAudiences = v.([]string)
		}
		if v, ok := d.GetOk("bound_subject"); ok {
			role.BoundSubject = v.(string)
		}
		if v, ok := d.GetOk("bound_claims"); ok {
			role.BoundClaims = v.(map[string]any)
		}
		if v, ok := d.GetOk("bound_uri_patterns"); ok {
			role.BoundURIPatterns = v.([]string)
		}
		if v, ok := d.GetOk("uri_claim"); ok {
			role.URIClaim = v.(string)
		}
		if v, ok := d.GetOk("token_policies"); ok {
			role.TokenPolicies = v.([]string)
		}
		if v, ok := d.GetOk("token_ttl"); ok {
			role.TokenTTL = (time.Duration(v.(int)) * time.Second).String()
		}
		if v, ok := d.GetOk("user_claim"); ok {
			role.UserClaim = v.(string)
		}
		if v, ok := d.GetOk("cred_spec_name"); ok {
			role.CredSpecName = v.(string)
		}
		if v, ok := d.GetOk("groups_claim"); ok {
			role.GroupsClaim = v.(string)
		}
		if v, ok := d.GetOk("group_policy_prefix"); ok {
			role.GroupPolicyPrefix = v.(string)
		}
		if v, ok := d.GetOk("max_age"); ok {
			role.MaxAge = v.(string)
		}
	}

	// Validate
	if err := b.validateRole(role); err != nil {
		return logical.ErrorResponse(err), nil
	}

	// Persist role
	if err := b.setRole(ctx, role); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	statusCode := http.StatusOK
	action := "updated"
	if isCreate {
		statusCode = http.StatusCreated
		action = "created"
	}

	return &logical.Response{
		StatusCode: statusCode,
		Data: map[string]any{
			"name":    role.Name,
			"message": fmt.Sprintf("Successfully %s role %s", action, name),
		},
	}, nil
}

// handleRoleDelete deletes a role
func (b *jwtAuthBackend) handleRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	if err := b.deleteRole(ctx, name); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"message": fmt.Sprintf("Successfully deleted role %s", name),
		},
	}, nil
}

// handleRoleList lists all roles
func (b *jwtAuthBackend) handleRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := b.listRoles(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data: map[string]any{
			"keys": roles,
		},
	}, nil
}

// validateRole validates role fields and sets defaults
func (b *jwtAuthBackend) validateRole(role *JWTRole) error {
	// Default user claim
	if role.UserClaim == "" {
		role.UserClaim = "sub"
	}

	// Token type is always jwt_role for JWT auth backends
	role.TokenType = "jwt_role"

	// Default TTL
	if role.TokenTTL == "" {
		role.TokenTTL = time.Hour.String()
	}
	if _, err := role.ParseTokenTTL(); err != nil {
		return logical.ErrBadRequestf("invalid token_ttl: %v", err)
	}

	// Validate URI patterns
	for _, p := range role.BoundURIPatterns {
		if err := helper.ValidatePattern(p); err != nil {
			return logical.ErrBadRequestf("invalid bound_uri_patterns pattern: %v", err)
		}
	}

	// Default URI claim to "sub" when patterns are configured
	if len(role.BoundURIPatterns) > 0 && role.URIClaim == "" {
		role.URIClaim = "sub"
	}

	// Validate max_age if provided
	if role.MaxAge != "" {
		maxAge, err := role.ParseMaxAge()
		if err != nil {
			return logical.ErrBadRequestf("invalid max_age: %v", err)
		}
		if maxAge <= 0 {
			return logical.ErrBadRequest("max_age must be a positive duration")
		}
	}

	return nil
}

// buildRoleFromFieldData creates a JWTRole from request field data
func (b *jwtAuthBackend) buildRoleFromFieldData(name string, d *framework.FieldData) *JWTRole {
	role := &JWTRole{
		Name: name,
	}

	if v, ok := d.GetOk("bound_audiences"); ok {
		role.BoundAudiences = v.([]string)
	}
	if v, ok := d.GetOk("bound_subject"); ok {
		role.BoundSubject = v.(string)
	}
	if v, ok := d.GetOk("bound_claims"); ok {
		role.BoundClaims = v.(map[string]any)
	}
	if v, ok := d.GetOk("bound_uri_patterns"); ok {
		role.BoundURIPatterns = v.([]string)
	}
	if v, ok := d.GetOk("uri_claim"); ok {
		role.URIClaim = v.(string)
	}
	if v, ok := d.GetOk("token_policies"); ok {
		role.TokenPolicies = v.([]string)
	}
	if v, ok := d.GetOk("token_ttl"); ok {
		role.TokenTTL = (time.Duration(v.(int)) * time.Second).String()
	}
	if v, ok := d.GetOk("user_claim"); ok {
		role.UserClaim = v.(string)
	}
	if v, ok := d.GetOk("cred_spec_name"); ok {
		role.CredSpecName = v.(string)
	}
	if v, ok := d.GetOk("groups_claim"); ok {
		role.GroupsClaim = v.(string)
	}
	if v, ok := d.GetOk("group_policy_prefix"); ok {
		role.GroupPolicyPrefix = v.(string)
	}
	if v, ok := d.GetOk("max_age"); ok {
		role.MaxAge = v.(string)
	}

	return role
}

// Storage helper methods

func (b *jwtAuthBackend) getRole(ctx context.Context, name string) (*JWTRole, error) {
	entry, err := b.storageView.Get(ctx, rolePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role JWTRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (b *jwtAuthBackend) setRole(ctx context.Context, role *JWTRole) error {
	entry, err := sdklogical.StorageEntryJSON(rolePrefix+role.Name, role)
	if err != nil {
		return err
	}

	return b.storageView.Put(ctx, entry)
}

func (b *jwtAuthBackend) deleteRole(ctx context.Context, name string) error {
	return b.storageView.Delete(ctx, rolePrefix+name)
}

func (b *jwtAuthBackend) listRoles(ctx context.Context) ([]string, error) {
	entries, err := b.storageView.List(ctx, rolePrefix)
	if err != nil {
		return nil, err
	}
	return entries, nil
}
