package spiffe

import (
	"context"
	"fmt"
	"net/http"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

const rolePrefix = "role/"

func (b *spiffeAuthBackend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name":        {Type: framework.TypeString, Description: "Name of the role", Required: true},
			"description": {Type: framework.TypeString, Description: "Human-readable description, surfaced via introspection"},
			"trust_domain": {
				Type:        framework.TypeString,
				Description: "SPIFFE trust domain this role binds to (required). An SVID validates only against this domain's bundle.",
			},
			"allowed_spiffe_ids": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Optional segment-aware SPIFFE ID patterns the verified SVID must match (e.g. spiffe://example.org/ns/+/sa/*)",
			},
			"bound_audiences": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Audiences accepted for JWT-SVID logins. Required for JWT-SVIDs; ignored for X.509-SVIDs.",
			},
			"token_policies": {Type: framework.TypeCommaStringSlice, Description: "Policies to assign to tokens"},
			"token_ttl":      {Type: framework.TypeDurationSecond, Description: "Token TTL", Default: 3600},
			"cred_spec_name": {Type: framework.TypeString, Description: "Credential spec name"},
			"groups_claim": {
				Type:        framework.TypeString,
				Description: "JWT-SVID claim containing group names for dynamic policy mapping (JWT-SVID only)",
			},
			"group_policy_prefix": {
				Type:        framework.TypeString,
				Description: "Prefix prepended to each group name to form the policy name (default: group-)",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.handleRoleCreate, Summary: "Create a new role"},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleRoleRead, Summary: "Read role configuration"},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleRoleUpdate, Summary: "Update role configuration"},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.handleRoleDelete, Summary: "Delete a role"},
		},
		HelpSynopsis:    "Manage SPIFFE auth roles",
		HelpDescription: "Create, read, update, and delete roles binding a SPIFFE trust domain to token policies.",
	}
}

func (b *spiffeAuthBackend) pathRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.handleRoleList, Summary: "List all roles"},
		},
		HelpSynopsis:    "List SPIFFE auth roles",
		HelpDescription: "List all configured roles.",
	}
}

func (b *spiffeAuthBackend) handleRoleCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	existing, err := b.getRole(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if existing != nil {
		return logical.ErrorResponse(logical.ErrConflictf("role %q already exists", name)), nil
	}

	role := b.buildRoleFromFieldData(name, d)
	if err := b.validateRole(role); err != nil {
		return logical.ErrorResponse(err), nil
	}
	if err := b.setRole(ctx, role); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	resp := &logical.Response{
		StatusCode: http.StatusCreated,
		Data:       map[string]any{"name": role.Name, "message": fmt.Sprintf("Successfully created role %s", name)},
	}
	addAudienceWarning(resp, role)
	return resp, nil
}

func (b *spiffeAuthBackend) handleRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
			"description":         role.Description,
			"trust_domain":        role.TrustDomain,
			"allowed_spiffe_ids":  role.AllowedSPIFFEIDs,
			"bound_audiences":     role.BoundAudiences,
			"token_policies":      role.TokenPolicies,
			"token_ttl":           role.TokenTTL,
			"cred_spec_name":      role.CredSpecName,
			"groups_claim":        role.GroupsClaim,
			"group_policy_prefix": role.GroupPolicyPrefix,
		},
	}, nil
}

func (b *spiffeAuthBackend) handleRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := b.getRole(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	isCreate := role == nil
	if isCreate {
		role = b.buildRoleFromFieldData(name, d)
	} else {
		if v, ok := d.GetOk("description"); ok {
			role.Description = v.(string)
		}
		if v, ok := d.GetOk("trust_domain"); ok {
			role.TrustDomain = v.(string)
		}
		if v, ok := d.GetOk("allowed_spiffe_ids"); ok {
			role.AllowedSPIFFEIDs = v.([]string)
		}
		if v, ok := d.GetOk("bound_audiences"); ok {
			role.BoundAudiences = v.([]string)
		}
		if v, ok := d.GetOk("token_policies"); ok {
			role.TokenPolicies = v.([]string)
		}
		if v, ok := d.GetOk("token_ttl"); ok {
			role.TokenTTL = (time.Duration(v.(int)) * time.Second).String()
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
	}

	if err := b.validateRole(role); err != nil {
		return logical.ErrorResponse(err), nil
	}
	if err := b.setRole(ctx, role); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	statusCode := http.StatusOK
	action := "updated"
	if isCreate {
		statusCode = http.StatusCreated
		action = "created"
	}
	resp := &logical.Response{
		StatusCode: statusCode,
		Data:       map[string]any{"name": role.Name, "message": fmt.Sprintf("Successfully %s role %s", action, name)},
	}
	addAudienceWarning(resp, role)
	return resp, nil
}

func (b *spiffeAuthBackend) handleRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := b.deleteRole(ctx, name); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"message": fmt.Sprintf("Successfully deleted role %s", name)}}, nil
}

func (b *spiffeAuthBackend) handleRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roles, err := b.listRoles(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	return &logical.Response{StatusCode: http.StatusOK, Data: map[string]any{"keys": roles}}, nil
}

// validateRole validates fields and sets defaults. trust_domain is required and
// must parse; allowed_spiffe_ids patterns must be valid. bound_audiences is not
// required at write time (it is enforced fail-closed at JWT-SVID login).
func (b *spiffeAuthBackend) validateRole(role *SPIFFERole) error {
	role.TokenType = "spiffe_role"

	if role.TrustDomain == "" {
		return logical.ErrBadRequest("trust_domain is required")
	}
	if _, err := spiffeid.TrustDomainFromString(role.TrustDomain); err != nil {
		return logical.ErrBadRequestf("invalid trust_domain %q: %v", role.TrustDomain, err)
	}
	for _, p := range role.AllowedSPIFFEIDs {
		if err := helper.ValidatePattern(p); err != nil {
			return logical.ErrBadRequestf("invalid allowed_spiffe_ids pattern: %v", err)
		}
	}
	if role.TokenTTL == "" {
		role.TokenTTL = time.Hour.String()
	}
	if _, err := role.ParseTokenTTL(); err != nil {
		return logical.ErrBadRequestf("invalid token_ttl: %v", err)
	}
	return nil
}

// addAudienceWarning notes that a role with no bound_audiences cannot accept
// JWT-SVID logins (they fail closed), while remaining usable for X.509-SVIDs.
func addAudienceWarning(resp *logical.Response, role *SPIFFERole) {
	if len(role.BoundAudiences) == 0 {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("role %q has no bound_audiences; JWT-SVID logins for it will be rejected (X.509-SVID logins are unaffected)", role.Name))
	}
}

func (b *spiffeAuthBackend) buildRoleFromFieldData(name string, d *framework.FieldData) *SPIFFERole {
	role := &SPIFFERole{Name: name}
	if v, ok := d.GetOk("description"); ok {
		role.Description = v.(string)
	}
	if v, ok := d.GetOk("trust_domain"); ok {
		role.TrustDomain = v.(string)
	}
	if v, ok := d.GetOk("allowed_spiffe_ids"); ok {
		role.AllowedSPIFFEIDs = v.([]string)
	}
	if v, ok := d.GetOk("bound_audiences"); ok {
		role.BoundAudiences = v.([]string)
	}
	if v, ok := d.GetOk("token_policies"); ok {
		role.TokenPolicies = v.([]string)
	}
	if v, ok := d.GetOk("token_ttl"); ok {
		role.TokenTTL = (time.Duration(v.(int)) * time.Second).String()
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
	return role
}

// --- storage ---

func (b *spiffeAuthBackend) getRole(ctx context.Context, name string) (*SPIFFERole, error) {
	entry, err := b.storageView.Get(ctx, rolePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var role SPIFFERole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func (b *spiffeAuthBackend) setRole(ctx context.Context, role *SPIFFERole) error {
	entry, err := sdklogical.StorageEntryJSON(rolePrefix+role.Name, role)
	if err != nil {
		return err
	}
	return b.storageView.Put(ctx, entry)
}

func (b *spiffeAuthBackend) deleteRole(ctx context.Context, name string) error {
	return b.storageView.Delete(ctx, rolePrefix+name)
}

func (b *spiffeAuthBackend) listRoles(ctx context.Context) ([]string, error) {
	return b.storageView.List(ctx, rolePrefix)
}
