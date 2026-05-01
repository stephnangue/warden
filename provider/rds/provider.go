// Package rds is an access backend that vends ready-to-use database
// connection strings backed by RDS / Aurora IAM authentication tokens
// (PostgreSQL and MySQL).
package rds

import (
	"fmt"
	"net/url"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/dbaccess"
)

// Spec declares the RDS access backend.
var Spec = &dbaccess.ProviderSpec{
	Name: "rds",
	GrantFields: map[string]*framework.FieldSchema{
		"db_name": {
			Type:        framework.TypeString,
			Description: "Database name to include in the connection string",
		},
		"db_engine": {
			Type:        framework.TypeString,
			Description: "Database engine (postgres, mysql). Overrides the spec value if set.",
		},
	},
	FormatAccess: formatAccess,
	HelpText:     rdsBackendHelp,
}

// Factory creates a new RDS access backend.
var Factory = dbaccess.NewFactory(Spec)

// formatAccess builds an engine-specific DSN. The grant's db_engine takes
// precedence so an operator can pin a grant to a specific engine even when
// the credential spec is more permissive; falls back to the engine carried
// on the minted credential.
func formatAccess(cred *credential.Credential, grant dbaccess.Grant, principal string) map[string]interface{} {
	host := cred.Data["db_host"]
	port := cred.Data["db_port"]
	user := cred.Data["db_user"]
	token := cred.Data["auth_token"]
	dbName := grant["db_name"]

	engine := grant["db_engine"]
	if engine == "" {
		engine = cred.Data["db_engine"]
	}

	var connStr string
	switch engine {
	case "mysql":
		connStr = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?tls=true&connectionAttributes=program_name:%s",
			user, url.QueryEscape(token), host, port, dbName, principal)
	default: // postgres
		connStr = fmt.Sprintf("host=%s port=%s dbname=%s user=%s password=%s sslmode=require application_name=%s",
			host, port, dbName, user, token, principal)
	}

	return map[string]interface{}{
		"connection_string": connStr,
		"lease_duration":    int(cred.LeaseTTL.Seconds()),
	}
}

const rdsBackendHelp = `
The RDS provider vends short-lived database connection strings backed by IAM
authentication. Workloads call /rds/access/<grant-name> to receive a ready-to-
use DSN; Warden does not proxy database traffic.

Supports PostgreSQL and MySQL on Amazon RDS and Aurora via the
rds_iam_token credential mint method.

Configuration:
- auto_auth_path: Auth mount path for implicit authentication (e.g. 'auth/jwt/')

Grants (path: rds/grants/<name>):
- credential_spec: Credential spec name to mint for this grant (required)
- db_name:         Database name to include in the connection string
- db_engine:       Database engine (postgres, mysql). Overrides the credential
                   spec's engine when set.
- description:     Human-readable description
`
