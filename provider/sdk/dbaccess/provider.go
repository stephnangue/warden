// Package dbaccess provides a declarative framework for database "access"
// backends — providers that vend short-lived database connection strings via
// a grants/access path pattern. Concrete providers (rds, redshift, …) declare
// a ProviderSpec and call NewFactory; all CRUD plumbing, storage, transparent
// auth, and access-endpoint wiring is handled by the framework.
//
// This mirrors the shape of provider/sdk/httpproxy for streaming providers.
package dbaccess

import (
	"context"
	"encoding/json"
	"fmt"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// Grant is a provider-defined map of grant fields. The framework adds
// credential_spec and description automatically; provider-specific fields
// come from ProviderSpec.GrantFields.
type Grant map[string]string

// FormatAccessFunc builds the access response from the minted credential, the
// resolved grant, and the requesting principal. Returned map is delivered to
// the caller as the response body.
type FormatAccessFunc func(cred *credential.Credential, grant Grant, principal string) map[string]interface{}

// ProviderSpec fully declares a database access provider.
type ProviderSpec struct {
	// Name is the provider identifier (e.g. "rds", "redshift").
	Name string

	// HelpText is the backend help description.
	HelpText string

	// GrantFields are provider-specific grant fields. credential_spec and
	// description are added automatically by the framework — do not include
	// them here.
	GrantFields map[string]*framework.FieldSchema

	// FormatAccess builds the response body for /access/{name}. Required.
	FormatAccess FormatAccessFunc
}

// NewFactory returns a logical.Factory wired up from spec.
func NewFactory(spec *ProviderSpec) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		if spec.Name == "" {
			return nil, fmt.Errorf("dbaccess: ProviderSpec.Name is required")
		}
		if spec.FormatAccess == nil {
			return nil, fmt.Errorf("dbaccess: ProviderSpec.FormatAccess is required")
		}

		b := &dbBackend{spec: spec}
		b.AccessBackend = &framework.AccessBackend{
			Backend: &framework.Backend{
				BackendType:  spec.Name,
				BackendClass: logical.ClassProvider,
				Help:         spec.HelpText,
			},
			Logger: conf.Logger.WithSubsystem(spec.Name),
		}
		b.Backend.Paths = b.paths()
		if err := b.AccessBackend.Setup(ctx, conf); err != nil {
			return nil, err
		}
		return b, nil
	}
}

// dbBackend is the shared backend type used by all dbaccess providers.
type dbBackend struct {
	*framework.AccessBackend
	spec *ProviderSpec
}

func (b *dbBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.PathAccessConfig(),
		b.pathGrants(),
		b.pathAccess(),
	}
}

// --- Grants CRUD ---

func (b *dbBackend) pathGrants() *framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Grant name",
		},
		"credential_spec": {
			Type:        framework.TypeString,
			Description: "Credential spec name to mint for this grant",
		},
		"description": {
			Type:        framework.TypeString,
			Description: "Human-readable description of this grant",
		},
	}
	for name, schema := range b.spec.GrantFields {
		// Provider-specified fields override the framework defaults if names
		// collide. Collisions on "name" / "credential_spec" / "description"
		// are programmer error and we silently let the provider win — the
		// framework still requires credential_spec at write time.
		fields[name] = schema
	}

	return &framework.Path{
		Pattern: "grants/(?P<name>[^/]+)",
		Fields:  fields,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleGrantRead,
				Summary:  "Read a grant",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleGrantWrite,
				Summary:  "Create or update a grant",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.handleGrantDelete,
				Summary:  "Delete a grant",
			},
		},
		HelpSynopsis:    "Manage " + b.spec.Name + " access grants",
		HelpDescription: "Grants map a name to a credential spec and database configuration.",
	}
}

func (b *dbBackend) handleGrantRead(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	grant, err := b.getGrant(ctx, name)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("grant %q not found", name)), nil
	}

	data := make(map[string]any, len(grant))
	for k, v := range grant {
		data[k] = v
	}
	return &logical.Response{StatusCode: 200, Data: data}, nil
}

func (b *dbBackend) handleGrantWrite(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	credSpec, _ := d.Get("credential_spec").(string)
	if credSpec == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("credential_spec is required")), nil
	}

	grant := Grant{
		"credential_spec": credSpec,
	}
	if desc, ok := d.Get("description").(string); ok && desc != "" {
		grant["description"] = desc
	}
	for fieldName := range b.spec.GrantFields {
		if v, ok := d.Get(fieldName).(string); ok && v != "" {
			grant[fieldName] = v
		}
	}

	if err := b.putGrant(ctx, name, grant); err != nil {
		return nil, err
	}
	return &logical.Response{StatusCode: 204}, nil
}

func (b *dbBackend) handleGrantDelete(ctx context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := b.StorageView.Delete(ctx, "grants/"+name); err != nil {
		return nil, err
	}
	return &logical.Response{StatusCode: 204}, nil
}

func (b *dbBackend) getGrant(ctx context.Context, name string) (Grant, error) {
	entry, err := b.StorageView.Get(ctx, "grants/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var grant Grant
	if err := json.Unmarshal(entry.Value, &grant); err != nil {
		return nil, fmt.Errorf("failed to decode grant %q: %w", name, err)
	}
	return grant, nil
}

func (b *dbBackend) putGrant(ctx context.Context, name string, grant Grant) error {
	entry, err := sdklogical.StorageEntryJSON("grants/"+name, grant)
	if err != nil {
		return err
	}
	return b.StorageView.Put(ctx, entry)
}

// --- Access endpoint ---

func (b *dbBackend) pathAccess() *framework.Path {
	return &framework.Path{
		Pattern: "access/(?P<name>[^/]+)",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Grant name",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleGetAccess,
				Summary:  "Get a database connection string for the given grant",
			},
		},
		HelpSynopsis:    "Get database access",
		HelpDescription: "Returns a ready-to-use connection string with IAM authentication.",
	}
}

func (b *dbBackend) handleGetAccess(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	grantName := d.Get("name").(string)
	grant, err := b.getGrant(ctx, grantName)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("grant %q not found", grantName)), nil
	}

	principal := ""
	if te := req.TokenEntry(); te != nil {
		principal = te.PrincipalID
	}

	credSpec := grant["credential_spec"]
	format := b.spec.FormatAccess
	return &logical.Response{
		AccessData: &logical.AccessData{
			CredentialSpec: credSpec,
			ResponseBuilder: func(cred *credential.Credential) map[string]interface{} {
				return format(cred, grant, principal)
			},
		},
	}, nil
}
