package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"time"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"

	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

const rolePrefix = "role/"

// pathRole returns the role CRUD path definition.
func (b *kubernetesAuthBackend) pathRole() *framework.Path {
	return &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
			"description": {
				Type:        framework.TypeString,
				Description: "Human-readable description, surfaced via introspection so agents can select an appropriate role",
			},
			"bound_service_account_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: `List of service account names the workload's SA must match. "*" matches any. At least one of bound_service_account_names or bound_service_account_namespaces must be a concrete value (refusing both as ["*"]).`,
			},
			"bound_service_account_namespaces": {
				Type:        framework.TypeCommaStringSlice,
				Description: `List of namespaces the workload's SA must live in. "*" matches any. At least one of bound_service_account_names or bound_service_account_namespaces must be a concrete value.`,
			},
			"audience": {
				Type:        framework.TypeString,
				Description: "If set, sent as spec.audiences in the TokenReview request. The workload JWT must declare this audience or the kube-apiserver rejects the review.",
			},
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of policies attached to issued tokens",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token TTL (default: 1h). Overrides the auth method's config token_ttl.",
				Default:     3600,
			},
			"cred_spec_name": {
				Type:        framework.TypeString,
				Description: "Credential spec name for implicit auth flows",
			},
			"max_age": {
				Type:        framework.TypeString,
				Description: `Maximum elapsed time since the JWT was issued (iat). Rejects JWTs older than this. Example: "30m", "1h"`,
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
		HelpSynopsis:    "Manage kubernetes auth roles",
		HelpDescription: "Create, read, update, and delete roles for kubernetes authentication.",
	}
}

// pathRoleList returns the role list path definition.
func (b *kubernetesAuthBackend) pathRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleRoleList,
				Summary:  "List all roles",
			},
		},
		HelpSynopsis:    "List kubernetes auth roles",
		HelpDescription: "List all configured roles for kubernetes authentication.",
	}
}

func (b *kubernetesAuthBackend) handleRoleCreate(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	return &logical.Response{
		StatusCode: http.StatusCreated,
		Data: map[string]any{
			"name":    role.Name,
			"message": fmt.Sprintf("Successfully created role %s", name),
		},
	}, nil
}

func (b *kubernetesAuthBackend) handleRoleRead(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
			"name":                             role.Name,
			"description":                      role.Description,
			"bound_service_account_names":      role.BoundServiceAccountNames,
			"bound_service_account_namespaces": role.BoundServiceAccountNamespaces,
			"audience":                         role.Audience,
			"token_policies":                   role.TokenPolicies,
			"token_ttl":                        role.TokenTTL,
			"cred_spec_name":                   role.CredSpecName,
			"max_age":                          role.MaxAge,
		},
	}, nil
}

func (b *kubernetesAuthBackend) handleRoleUpdate(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.getRole(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	isCreate := role == nil
	if isCreate {
		role = b.buildRoleFromFieldData(name, d)
	} else {
		// Update existing role — only touch fields explicitly provided.
		if v, ok := d.GetOk("description"); ok {
			role.Description = v.(string)
		}
		if v, ok := d.GetOk("bound_service_account_names"); ok {
			role.BoundServiceAccountNames = v.([]string)
		}
		if v, ok := d.GetOk("bound_service_account_namespaces"); ok {
			role.BoundServiceAccountNamespaces = v.([]string)
		}
		if v, ok := d.GetOk("audience"); ok {
			role.Audience = v.(string)
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
		if v, ok := d.GetOk("max_age"); ok {
			role.MaxAge = v.(string)
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

	return &logical.Response{
		StatusCode: statusCode,
		Data: map[string]any{
			"name":    role.Name,
			"message": fmt.Sprintf("Successfully %s role %s", action, name),
		},
	}, nil
}

func (b *kubernetesAuthBackend) handleRoleDelete(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	if err := b.deleteRole(ctx, name); err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}

	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"message": fmt.Sprintf("Successfully deleted role %s", name)},
	}, nil
}

func (b *kubernetesAuthBackend) handleRoleList(ctx context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := b.listRoles(ctx)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	return &logical.Response{
		StatusCode: http.StatusOK,
		Data:       map[string]any{"keys": roles},
	}, nil
}

// validateRole validates role fields and sets defaults. TokenType is
// always pinned to "kubernetes_role" so operators can't override it.
func (b *kubernetesAuthBackend) validateRole(role *KubernetesRole) error {
	role.TokenType = "kubernetes_role"

	if role.TokenTTL == "" {
		role.TokenTTL = time.Hour.String()
	}
	if _, err := role.ParseTokenTTL(); err != nil {
		return logical.ErrBadRequestf("invalid token_ttl: %v", err)
	}

	// At least one of names/namespaces must be a concrete value. Both empty
	// or both ["*"] would let any K8s workload that can reach the spoke get
	// this role — refuse it (defense in depth, matches Vault's behavior).
	if onlyWildcardOrEmpty(role.BoundServiceAccountNames) && onlyWildcardOrEmpty(role.BoundServiceAccountNamespaces) {
		return logical.ErrBadRequest("at least one of bound_service_account_names or bound_service_account_namespaces must contain a concrete value (not empty, not only \"*\")")
	}

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

// onlyWildcardOrEmpty returns true if the list is empty or contains only
// "*" entries. Used by validateRole to refuse roles bound to nothing
// concrete.
func onlyWildcardOrEmpty(list []string) bool {
	if len(list) == 0 {
		return true
	}
	for _, v := range list {
		if v != "*" {
			return false
		}
	}
	return true
}

// buildRoleFromFieldData creates a KubernetesRole from request field data.
func (b *kubernetesAuthBackend) buildRoleFromFieldData(name string, d *framework.FieldData) *KubernetesRole {
	role := &KubernetesRole{Name: name}

	if v, ok := d.GetOk("description"); ok {
		role.Description = v.(string)
	}
	if v, ok := d.GetOk("bound_service_account_names"); ok {
		role.BoundServiceAccountNames = v.([]string)
	}
	if v, ok := d.GetOk("bound_service_account_namespaces"); ok {
		role.BoundServiceAccountNamespaces = v.([]string)
	}
	if v, ok := d.GetOk("audience"); ok {
		role.Audience = v.(string)
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
	if v, ok := d.GetOk("max_age"); ok {
		role.MaxAge = v.(string)
	}

	return role
}

// Storage helpers — JSON-encoded under role/<name>.

func (b *kubernetesAuthBackend) getRole(ctx context.Context, name string) (*KubernetesRole, error) {
	entry, err := b.storageView.Get(ctx, rolePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var role KubernetesRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

func (b *kubernetesAuthBackend) setRole(ctx context.Context, role *KubernetesRole) error {
	entry, err := sdklogical.StorageEntryJSON(rolePrefix+role.Name, role)
	if err != nil {
		return err
	}
	return b.storageView.Put(ctx, entry)
}

func (b *kubernetesAuthBackend) deleteRole(ctx context.Context, name string) error {
	return b.storageView.Delete(ctx, rolePrefix+name)
}

func (b *kubernetesAuthBackend) listRoles(ctx context.Context) ([]string, error) {
	return b.storageView.List(ctx, rolePrefix)
}
