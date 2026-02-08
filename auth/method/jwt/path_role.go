package jwt

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
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
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of policies to assign to tokens",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token TTL",
				Default:     3600,
			},
			"token_type": {
				Type:          framework.TypeString,
				Description:   "Token type",
				Required:      true,
				AllowedValues: b.allowedTokenTypeValues(),
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

// isValidTokenType checks if the given token type is valid
func (b *jwtAuthBackend) isValidTokenType(tokenType string) bool {
	return slices.Contains(b.validTokenTypes, tokenType)
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

	// Set defaults
	if role.UserClaim == "" {
		role.UserClaim = "sub"
	}
	// Use config's token_type as default if not specified in role
	if role.TokenType == "" && b.config != nil && b.config.TokenType != "" {
		role.TokenType = b.config.TokenType
	}

	// Validate token type
	if role.TokenType == "" {
		return logical.ErrorResponse(logical.ErrBadRequestf("token_type is required; must be one of: %v", b.validTokenTypes)), nil
	}
	if !b.isValidTokenType(role.TokenType) {
		return logical.ErrorResponse(logical.ErrBadRequestf("invalid token_type %q; must be one of: %v", role.TokenType, b.validTokenTypes)), nil
	}
	if role.TokenTTL == 0 {
		role.TokenTTL = time.Hour
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
			"name":           role.Name,
			"bound_audiences": role.BoundAudiences,
			"bound_subject":  role.BoundSubject,
			"bound_claims":   role.BoundClaims,
			"token_policies": role.TokenPolicies,
			"token_ttl":      role.TokenTTL.String(),
			"token_type":     role.TokenType,
			"user_claim":     role.UserClaim,
			"cred_spec_name": role.CredSpecName,
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
		// Create new role from field data
		role = b.buildRoleFromFieldData(name, d)

		// Set defaults for new roles
		if role.UserClaim == "" {
			role.UserClaim = "sub"
		}
		// Use config's token_type as default if not specified in role
		if role.TokenType == "" && b.config != nil && b.config.TokenType != "" {
			role.TokenType = b.config.TokenType
		}
		if role.TokenTTL == 0 {
			role.TokenTTL = time.Hour
		}
	} else {
		// Update existing role - only update fields that are provided
		if v, ok := d.GetOk("bound_audiences"); ok {
			role.BoundAudiences = v.([]string)
		}
		if v, ok := d.GetOk("bound_subject"); ok {
			role.BoundSubject = v.(string)
		}
		if v, ok := d.GetOk("bound_claims"); ok {
			role.BoundClaims = v.(map[string]any)
		}
		if v, ok := d.GetOk("token_policies"); ok {
			role.TokenPolicies = v.([]string)
		}
		if v, ok := d.GetOk("token_ttl"); ok {
			role.TokenTTL = time.Duration(v.(int)) * time.Second
		}
		if v, ok := d.GetOk("token_type"); ok {
			role.TokenType = v.(string)
		}
		if v, ok := d.GetOk("user_claim"); ok {
			role.UserClaim = v.(string)
		}
		if v, ok := d.GetOk("cred_spec_name"); ok {
			role.CredSpecName = v.(string)
		}
	}

	// Validate token type
	if role.TokenType == "" {
		return logical.ErrorResponse(logical.ErrBadRequestf("token_type is required; must be one of: %v", b.validTokenTypes)), nil
	}
	if !b.isValidTokenType(role.TokenType) {
		return logical.ErrorResponse(logical.ErrBadRequestf("invalid token_type %q; must be one of: %v", role.TokenType, b.validTokenTypes)), nil
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
	if v, ok := d.GetOk("token_policies"); ok {
		role.TokenPolicies = v.([]string)
	}
	if v, ok := d.GetOk("token_ttl"); ok {
		role.TokenTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := d.GetOk("token_type"); ok {
		role.TokenType = v.(string)
	}
	if v, ok := d.GetOk("user_claim"); ok {
		role.UserClaim = v.(string)
	}
	if v, ok := d.GetOk("cred_spec_name"); ok {
		role.CredSpecName = v.(string)
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

	var stored StoredRole
	if err := entry.DecodeJSON(&stored); err != nil {
		return nil, err
	}

	// Convert stored format to runtime format
	tokenTTL, _ := time.ParseDuration(stored.TokenTTL)

	return &JWTRole{
		Name:           stored.Name,
		BoundAudiences: stored.BoundAudiences,
		BoundSubject:   stored.BoundSubject,
		BoundClaims:    stored.BoundClaims,
		TokenPolicies:  stored.TokenPolicies,
		TokenTTL:       tokenTTL,
		TokenType:      stored.TokenType,
		UserClaim:      stored.UserClaim,
		CredSpecName:   stored.CredSpecName,
	}, nil
}

func (b *jwtAuthBackend) setRole(ctx context.Context, role *JWTRole) error {
	stored := StoredRole{
		Name:           role.Name,
		BoundAudiences: role.BoundAudiences,
		BoundSubject:   role.BoundSubject,
		BoundClaims:    role.BoundClaims,
		TokenPolicies:  role.TokenPolicies,
		TokenTTL:       role.TokenTTL.String(),
		TokenType:      role.TokenType,
		UserClaim:      role.UserClaim,
		CredSpecName:   role.CredSpecName,
	}

	entry, err := sdklogical.StorageEntryJSON(rolePrefix+role.Name, stored)
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
