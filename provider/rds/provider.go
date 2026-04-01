package rds

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	sdklogical "github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/logical"
)

// rdsBackend is an access backend that vends database connection strings
// using RDS IAM authentication tokens.
type rdsBackend struct {
	*framework.AccessBackend
}

// rdsGrant maps a grant name to a credential spec and database configuration.
type rdsGrant struct {
	CredentialSpec string `json:"credential_spec"`
	DBName         string `json:"db_name"`
	DBEngine       string `json:"db_engine"`
	Description    string `json:"description,omitempty"`
}

// Factory creates a new RDS access backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &rdsBackend{}
	b.AccessBackend = &framework.AccessBackend{
		Backend: &framework.Backend{
			BackendType:  "rds",
			BackendClass: logical.ClassProvider,
		},
		Logger: conf.Logger.WithSubsystem("rds"),
	}
	b.Backend.Paths = b.paths()
	if err := b.AccessBackend.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *rdsBackend) paths() []*framework.Path {
	return []*framework.Path{
		b.PathAccessConfig(),
		b.pathGrants(),
		b.pathAccess(),
	}
}

// --- Grants CRUD ---

func (b *rdsBackend) pathGrants() *framework.Path {
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
			"db_engine": {
				Type:        framework.TypeString,
				Description: "Database engine (postgres, mysql). Overrides the spec value if set.",
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
		HelpSynopsis:    "Manage RDS access grants",
		HelpDescription: "Grants map a name to a credential spec and database configuration.",
	}
}

func (b *rdsBackend) handleGrantRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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
			"db_engine":       grant.DBEngine,
			"description":     grant.Description,
		},
	}, nil
}

func (b *rdsBackend) handleGrantWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	credSpec, _ := d.Get("credential_spec").(string)
	if credSpec == "" {
		return logical.ErrorResponse(logical.ErrBadRequest("credential_spec is required")), nil
	}

	grant := &rdsGrant{
		CredentialSpec: credSpec,
		DBName:         d.Get("db_name").(string),
		DBEngine:       d.Get("db_engine").(string),
		Description:    d.Get("description").(string),
	}

	if err := b.putGrant(ctx, name, grant); err != nil {
		return nil, err
	}

	return &logical.Response{StatusCode: 204}, nil
}

func (b *rdsBackend) handleGrantDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if err := b.StorageView.Delete(ctx, "grants/"+name); err != nil {
		return nil, err
	}
	return &logical.Response{StatusCode: 204}, nil
}

func (b *rdsBackend) getGrant(ctx context.Context, name string) (*rdsGrant, error) {
	entry, err := b.StorageView.Get(ctx, "grants/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var grant rdsGrant
	if err := json.Unmarshal(entry.Value, &grant); err != nil {
		return nil, fmt.Errorf("failed to decode grant %q: %w", name, err)
	}
	return &grant, nil
}

func (b *rdsBackend) putGrant(ctx context.Context, name string, grant *rdsGrant) error {
	entry, err := sdklogical.StorageEntryJSON("grants/"+name, grant)
	if err != nil {
		return err
	}
	return b.StorageView.Put(ctx, entry)
}

// --- Access endpoint ---

func (b *rdsBackend) pathAccess() *framework.Path {
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

func (b *rdsBackend) handleGetAccess(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

// formatConnectionString builds a ready-to-use DSN from the minted credential,
// grant config, and the requesting principal (for attribution).
func formatConnectionString(cred *credential.Credential, grant *rdsGrant, principal string) string {
	host := cred.Data["db_host"]
	port := cred.Data["db_port"]
	user := cred.Data["db_user"]
	token := cred.Data["auth_token"]
	dbName := grant.DBName
	engine := grant.DBEngine
	if engine == "" {
		engine = cred.Data["db_engine"]
	}

	switch engine {
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?tls=true&connectionAttributes=program_name:%s",
			user, url.QueryEscape(token), host, port, dbName, principal)
	default: // postgres
		return fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=require application_name=%s",
			host, port, dbName, user, token, principal)
	}
}
