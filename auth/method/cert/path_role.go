package cert

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/auth/helper"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

const rolePrefix = "role/"

// pathRole returns the role CRUD path definition
func (b *certAuthBackend) pathRole() *framework.Path {
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
				Description: "Human-readable description of the role's purpose, surfaced via introspection so agents can select an appropriate role",
			},
			"allowed_common_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Glob patterns for allowed certificate common names",
			},
			"allowed_dns_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Glob patterns for allowed DNS SANs",
			},
			"allowed_email_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Glob patterns for allowed email SANs",
			},
			"allowed_uri_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Allowed URI SAN patterns using segment wildcards: '+' matches one segment, trailing '*' matches one or more segments (e.g., spiffe://+/ns/*/sa/*)",
			},
			"allowed_organizational_units": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Allowed organizational units",
			},
			"allowed_organizations": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Allowed organizations",
			},
			"certificate": {
				Type:        framework.TypeString,
				Description: "Role-specific CA PEM (overrides global trusted CAs). x509 mode only.",
			},
			"trust_domain": {
				Type:        framework.TypeString,
				Description: "SPIFFE trust domain this role authenticates (e.g. prod.example.org). Required in spiffe mode; not valid in x509 mode.",
			},
			"allowed_spiffe_ids": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Optional SPIFFE ID segment-wildcard patterns restricting the path within the trust domain (e.g. spiffe://prod.example.org/ns/*/sa/*). spiffe mode only.",
			},
			"token_policies": {
				Type:        framework.TypeCommaStringSlice,
				Description: "List of policies to assign to tokens",
			},
			"token_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Token TTL (default: 1h)",
				Default:     3600,
			},
			"cred_spec_name": {
				Type:        framework.TypeString,
				Description: "Credential spec name",
			},
			"principal_claim": {
				Type:          framework.TypeString,
				Description:   "Identity source from certificate (overrides global config): cn, dns_san, email_san, uri_san, serial",
				AllowedValues: principalClaimAllowedValues(),
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
		HelpSynopsis:    "Manage certificate auth roles",
		HelpDescription: "Create, read, update, and delete roles for certificate authentication.",
	}
}

// pathRoleList returns the role list path definition
func (b *certAuthBackend) pathRoleList() *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleRoleList,
				Summary:  "List all roles",
			},
		},
		HelpSynopsis:    "List certificate auth roles",
		HelpDescription: "List all configured roles for certificate authentication.",
	}
}

// handleRoleCreate creates a new role
func (b *certAuthBackend) handleRoleCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
func (b *certAuthBackend) handleRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	role, err := b.getRole(ctx, name)
	if err != nil {
		return logical.ErrorResponse(logical.ErrInternal(err.Error())), nil
	}
	if role == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("role %q not found", name)), nil
	}

	// Fields common to both modes.
	data := map[string]any{
		"name":           role.Name,
		"description":    role.Description,
		"token_policies": role.TokenPolicies,
		"token_ttl":      role.TokenTTL,
		"cred_spec_name": role.CredSpecName,
	}

	// Surface only the fields relevant to the mount's mode.
	if b.mountMode() == modeSPIFFE {
		data["trust_domain"] = role.TrustDomain
		data["allowed_spiffe_ids"] = role.AllowedSPIFFEIDs
	} else {
		data["allowed_common_names"] = role.AllowedCommonNames
		data["allowed_dns_sans"] = role.AllowedDNSSANs
		data["allowed_email_sans"] = role.AllowedEmailSANs
		data["allowed_uri_sans"] = role.AllowedURISANs
		data["allowed_organizational_units"] = role.AllowedOrganizationalUnits
		data["allowed_organizations"] = role.AllowedOrganizations
		data["certificate"] = role.Certificate
		data["principal_claim"] = role.PrincipalClaim
	}

	return &logical.Response{StatusCode: http.StatusOK, Data: data}, nil
}

// handleRoleUpdate updates an existing role or creates it if it doesn't exist (upsert pattern).
func (b *certAuthBackend) handleRoleUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
		if v, ok := d.GetOk("description"); ok {
			role.Description = v.(string)
		}
		if v, ok := d.GetOk("allowed_common_names"); ok {
			role.AllowedCommonNames = v.([]string)
		}
		if v, ok := d.GetOk("allowed_dns_sans"); ok {
			role.AllowedDNSSANs = v.([]string)
		}
		if v, ok := d.GetOk("allowed_email_sans"); ok {
			role.AllowedEmailSANs = v.([]string)
		}
		if v, ok := d.GetOk("allowed_uri_sans"); ok {
			role.AllowedURISANs = v.([]string)
		}
		if v, ok := d.GetOk("allowed_organizational_units"); ok {
			role.AllowedOrganizationalUnits = v.([]string)
		}
		if v, ok := d.GetOk("allowed_organizations"); ok {
			role.AllowedOrganizations = v.([]string)
		}
		if v, ok := d.GetOk("certificate"); ok {
			role.Certificate = v.(string)
		}
		if v, ok := d.GetOk("trust_domain"); ok {
			role.TrustDomain = v.(string)
		}
		if v, ok := d.GetOk("allowed_spiffe_ids"); ok {
			role.AllowedSPIFFEIDs = v.([]string)
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
		if v, ok := d.GetOk("principal_claim"); ok {
			role.PrincipalClaim = v.(string)
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
func (b *certAuthBackend) handleRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
func (b *certAuthBackend) handleRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

// validateRole validates role fields and sets defaults, dispatching to the
// mode-specific validator for the mount.
func (b *certAuthBackend) validateRole(role *CertRole) error {
	// Token type is always cert_role for cert auth backends
	role.TokenType = "cert_role"

	// Default TTL
	if role.TokenTTL == "" {
		role.TokenTTL = time.Hour.String()
	}
	// Validate the TTL parses
	if _, err := role.ParseTokenTTL(); err != nil {
		return logical.ErrBadRequestf("invalid token_ttl: %v", err)
	}

	if b.mountMode() == modeSPIFFE {
		return validateSPIFFERole(role)
	}
	return validateX509Role(role)
}

// validateX509Role validates a role on an x509-mode mount: at least one PKI
// constraint, valid patterns, and no SPIFFE-only fields.
func validateX509Role(role *CertRole) error {
	if role.TrustDomain != "" || len(role.AllowedSPIFFEIDs) > 0 {
		return logical.ErrBadRequest("trust_domain and allowed_spiffe_ids are only valid in spiffe mode")
	}

	// Require at least one certificate constraint to prevent overly permissive roles
	// that would accept any certificate signed by a trusted CA.
	if len(role.AllowedCommonNames) == 0 &&
		len(role.AllowedDNSSANs) == 0 &&
		len(role.AllowedEmailSANs) == 0 &&
		len(role.AllowedURISANs) == 0 &&
		len(role.AllowedOrganizationalUnits) == 0 &&
		len(role.AllowedOrganizations) == 0 {
		return logical.ErrBadRequest("at least one certificate constraint is required (allowed_common_names, allowed_dns_sans, allowed_email_sans, allowed_uri_sans, allowed_organizational_units, or allowed_organizations)")
	}

	// Validate glob patterns for CN, DNS SANs, and email SANs
	for _, p := range role.AllowedCommonNames {
		if _, err := path.Match(p, ""); err != nil {
			return logical.ErrBadRequestf("invalid allowed_common_names pattern %q: %v", p, err)
		}
	}
	for _, p := range role.AllowedDNSSANs {
		if _, err := path.Match(p, ""); err != nil {
			return logical.ErrBadRequestf("invalid allowed_dns_sans pattern %q: %v", p, err)
		}
	}
	for _, p := range role.AllowedEmailSANs {
		if _, err := path.Match(p, ""); err != nil {
			return logical.ErrBadRequestf("invalid allowed_email_sans pattern %q: %v", p, err)
		}
	}

	// Validate URI SAN segment-wildcard patterns
	for _, p := range role.AllowedURISANs {
		if err := helper.ValidatePattern(p); err != nil {
			return logical.ErrBadRequestf("invalid allowed_uri_sans pattern: %v", err)
		}
	}

	// Validate principal_claim if provided
	if role.PrincipalClaim != "" && !isValidPrincipalClaim(role.PrincipalClaim) {
		return logical.ErrBadRequestf("invalid principal_claim %q; must be one of: %v", role.PrincipalClaim, validPrincipalClaims)
	}

	// Validate role-specific CA PEM if provided
	if role.Certificate != "" {
		if _, err := buildCAPool(role.Certificate); err != nil {
			return logical.ErrBadRequestf("invalid certificate PEM: %v", err)
		}
	}

	return nil
}

// validateSPIFFERole validates a role on a spiffe-mode mount: a required, valid
// trust_domain, optional SPIFFE-ID patterns, and no PKI-only fields. The trust
// domain need not already be registered — it is resolved (fail-closed) at login.
func validateSPIFFERole(role *CertRole) error {
	if role.TrustDomain == "" {
		return logical.ErrBadRequest("trust_domain is required in spiffe mode")
	}
	if _, err := spiffeid.TrustDomainFromString(role.TrustDomain); err != nil {
		return logical.ErrBadRequestf("invalid trust_domain %q: %v", role.TrustDomain, err)
	}
	for _, p := range role.AllowedSPIFFEIDs {
		if err := helper.ValidatePattern(p); err != nil {
			return logical.ErrBadRequestf("invalid allowed_spiffe_ids pattern: %v", err)
		}
	}

	if len(role.AllowedCommonNames) > 0 ||
		len(role.AllowedDNSSANs) > 0 ||
		len(role.AllowedEmailSANs) > 0 ||
		len(role.AllowedURISANs) > 0 ||
		len(role.AllowedOrganizationalUnits) > 0 ||
		len(role.AllowedOrganizations) > 0 ||
		role.Certificate != "" ||
		role.PrincipalClaim != "" {
		return logical.ErrBadRequest("allowed_common_names, allowed_dns_sans, allowed_email_sans, allowed_uri_sans, allowed_organizational_units, allowed_organizations, certificate, and principal_claim are not valid in spiffe mode")
	}

	return nil
}

// buildRoleFromFieldData creates a CertRole from request field data
func (b *certAuthBackend) buildRoleFromFieldData(name string, d *framework.FieldData) *CertRole {
	role := &CertRole{
		Name: name,
	}

	if v, ok := d.GetOk("description"); ok {
		role.Description = v.(string)
	}
	if v, ok := d.GetOk("allowed_common_names"); ok {
		role.AllowedCommonNames = v.([]string)
	}
	if v, ok := d.GetOk("allowed_dns_sans"); ok {
		role.AllowedDNSSANs = v.([]string)
	}
	if v, ok := d.GetOk("allowed_email_sans"); ok {
		role.AllowedEmailSANs = v.([]string)
	}
	if v, ok := d.GetOk("allowed_uri_sans"); ok {
		role.AllowedURISANs = v.([]string)
	}
	if v, ok := d.GetOk("allowed_organizational_units"); ok {
		role.AllowedOrganizationalUnits = v.([]string)
	}
	if v, ok := d.GetOk("allowed_organizations"); ok {
		role.AllowedOrganizations = v.([]string)
	}
	if v, ok := d.GetOk("certificate"); ok {
		role.Certificate = v.(string)
	}
	if v, ok := d.GetOk("trust_domain"); ok {
		role.TrustDomain = v.(string)
	}
	if v, ok := d.GetOk("allowed_spiffe_ids"); ok {
		role.AllowedSPIFFEIDs = v.([]string)
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
	if v, ok := d.GetOk("principal_claim"); ok {
		role.PrincipalClaim = v.(string)
	}

	return role
}

// Storage helper methods

func (b *certAuthBackend) getRole(ctx context.Context, name string) (*CertRole, error) {
	entry, err := b.storageView.Get(ctx, rolePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role CertRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (b *certAuthBackend) setRole(ctx context.Context, role *CertRole) error {
	entry, err := sdklogical.StorageEntryJSON(rolePrefix+role.Name, role)
	if err != nil {
		return err
	}

	return b.storageView.Put(ctx, entry)
}

func (b *certAuthBackend) deleteRole(ctx context.Context, name string) error {
	return b.storageView.Delete(ctx, rolePrefix+name)
}

func (b *certAuthBackend) listRoles(ctx context.Context) ([]string, error) {
	entries, err := b.storageView.List(ctx, rolePrefix)
	if err != nil {
		return nil, err
	}
	return entries, nil
}
