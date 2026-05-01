// Package redshift is an access backend that vends ready-to-use postgres
// connection strings backed by Amazon Redshift IAM authentication tokens
// (provisioned clusters via redshift:GetClusterCredentialsWithIAM, serverless
// workgroups via redshift-serverless:GetCredentials).
package redshift

import (
	"fmt"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/framework"
	"github.com/stephnangue/warden/provider/dbaccess"
)

// Spec declares the Redshift access backend.
var Spec = &dbaccess.ProviderSpec{
	Name: "redshift",
	GrantFields: map[string]*framework.FieldSchema{
		"db_name": {
			Type:        framework.TypeString,
			Description: "Database name to include in the connection string",
		},
	},
	FormatAccess: formatAccess,
	HelpText:     redshiftBackendHelp,
}

// Factory creates a new Redshift access backend.
var Factory = dbaccess.NewFactory(Spec)

// formatAccess builds a libpq-style DSN. Redshift speaks the PostgreSQL wire
// protocol, so any postgres driver can use the result. The password from
// GetClusterCredentialsWithIAM / GetCredentials is wrapped in single quotes —
// libpq treats quoted values as opaque, sidestepping any special characters.
func formatAccess(cred *credential.Credential, grant dbaccess.Grant, principal string) map[string]interface{} {
	return map[string]interface{}{
		"connection_string": fmt.Sprintf(
			"host=%s port=%s dbname=%s user=%s password='%s' sslmode=require application_name=%s",
			cred.Data["db_host"],
			cred.Data["db_port"],
			grant["db_name"],
			cred.Data["db_user"],
			cred.Data["auth_token"],
			principal,
		),
		"lease_duration": int(cred.LeaseTTL.Seconds()),
	}
}

const redshiftBackendHelp = `
The Redshift provider vends short-lived postgres connection strings backed by
IAM authentication. Workloads call /redshift/access/<grant-name> to receive a
ready-to-use libpq DSN; Warden does not proxy database traffic.

Supports both deployment models — provisioned clusters and serverless
workgroups — via the same redshift_iam_token credential mint method.

Configuration:
- auto_auth_path: Auth mount path for implicit authentication (e.g. 'auth/jwt/')

Grants (path: redshift/grants/<name>):
- credential_spec: Credential spec name to mint for this grant (required)
- db_name:         Database name to include in the connection string
- description:     Human-readable description
`
