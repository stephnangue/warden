package redshift

import (
	"context"
	"encoding/json"
	"fmt"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// redshiftBackend is an access backend that vends database connection strings
// using Amazon Redshift IAM authentication tokens.
type redshiftBackend struct {
	*framework.AccessBackend
}

// redshiftGrant maps a grant name to a credential spec and database configuration.
type redshiftGrant struct {
	CredentialSpec string `json:"credential_spec"`
	DBName         string `json:"db_name"`
	Description    string `json:"description,omitempty"`
}

// Factory creates a new Redshift access backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &redshiftBackend{}
	b.AccessBackend = &framework.AccessBackend{
		Backend: &framework.Backend{
			BackendType:  "redshift",
			BackendClass: logical.ClassProvider,
		},
		Logger: conf.Logger.WithSubsystem("redshift"),
	}
	b.Backend.Paths = b.paths()
	if err := b.AccessBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *redshiftBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.PathAccessConfig(),
		b.pathGrants(),
		b.pathAccess(),
	}
}

// --- Grants CRUD ---

func (b *redshiftBackend) pathGrants() *framework.Path {
	return &framework.Path{
		Pattern: "grants/(?P<name>[^/]+)",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Grant name",
			},
			"credential_spec": {
				Type:        framework.TypeString,
				Description: "Credential spec name to mint for this grant",
			},
			"db_name": {
				Type:        framework.TypeString,
				Description: "Database name to include in the connection string",
			},
			"description": {
				Type:        framework.TypeString,
				Description: "Human-readable description of this grant",
			},
		},
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
		HelpSynopsis:    "Manage Redshift access grants",
		HelpDescription: "Grants map a name to a credential spec and database configuration.",
	}
}

func (b *redshiftBackend) handleGrantRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	grant, err := b.getGrant(ctx, name)
	if err != nil {
		return nil, err
	}
	if grant == nil {
		return logical.ErrorResponse(logical.ErrNotFoundf("grant %q not found", name)), nil
	}
	return &logical.Response{
		StatusCode: 200,
		Data: map[string]any{
			"credential_spec": grant.CredentialSpec,
			"db_name":         grant.DBName,
			"description":     grant.Description,
		},
	}, nil
}

func (b *redshiftBackend) handleGrantWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	credSpec, _ := d.Get("credential_spec").(string)
	if credSpec == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("credential_spec is required")), nil
	}

	grant := &redshiftGrant{
		CredentialSpec: credSpec,
		DBName:         d.Get("db_name").(string),
		Description:    d.Get("description").(string),
	}

	if err := b.putGrant(ctx, name, grant); err != nil {
		return nil, err
	}

	return &logical.Response{StatusCode: 204}, nil
}

func (b *redshiftBackend) handleGrantDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := b.StorageView.Delete(ctx, "grants/"+name); err != nil {
		return nil, err
	}
	return &logical.Response{StatusCode: 204}, nil
}

func (b *redshiftBackend) getGrant(ctx context.Context, name string) (*redshiftGrant, error) {
	entry, err := b.StorageView.Get(ctx, "grants/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var grant redshiftGrant
	if err := json.Unmarshal(entry.Value, &grant); err != nil {
		return nil, fmt.Errorf("failed to decode grant %q: %w", name, err)
	}
	return &grant, nil
}

func (b *redshiftBackend) putGrant(ctx context.Context, name string, grant *redshiftGrant) error {
	entry, err := sdklogical.StorageEntryJSON("grants/"+name, grant)
	if err != nil {
		return err
	}
	return b.StorageView.Put(ctx, entry)
}

// --- Access endpoint ---

func (b *redshiftBackend) pathAccess() *framework.Path {
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
		HelpDescription: "Returns a ready-to-use Redshift connection string with IAM authentication.",
	}
}

func (b *redshiftBackend) handleGetAccess(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	return &logical.Response{
		AccessData: &logical.AccessData{
			CredentialSpec: grant.CredentialSpec,
			ResponseBuilder: func(cred *credential.Credential) map[string]interface{} {
				return map[string]interface{}{
					"connection_string": formatConnectionString(cred, grant, principal),
					"lease_duration":    int(cred.LeaseTTL.Seconds()),
				}
			},
		},
	}, nil
}

// formatConnectionString builds a libpq-style DSN. Redshift speaks the
// PostgreSQL wire protocol, so any postgres driver can use this string.
// The password from GetClusterCredentialsWithIAM / GetCredentials is wrapped
// in single quotes — libpq treats quoted values as opaque, sidestepping any
// special characters.
func formatConnectionString(cred *credential.Credential, grant *redshiftGrant, principal string) string {
	host := cred.Data["db_host"]
	port := cred.Data["db_port"]
	user := cred.Data["db_user"]
	password := cred.Data["auth_token"]
	dbName := grant.DBName

	return fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password='%s' sslmode=require application_name=%s",
		host, port, dbName, user, password, principal,
	)
}
