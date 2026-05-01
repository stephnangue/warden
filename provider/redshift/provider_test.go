package redshift

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/provider/sdk/dbaccess"
	"github.com/stretchr/testify/assert"
)

// Standard backend behavior (Factory wiring, config CRUD, grant CRUD,
// transparent mode, access-endpoint plumbing, role query parameter) is
// covered by provider/sdk/dbaccess/provider_test.go against the shared
// framework. These tests cover only the Redshift-specific formatter.

func TestFormatAccess_ProvisionedCluster(t *testing.T) {
	cred := &credential.Credential{
		Data: map[string]string{
			"auth_token": "secret-token",
			"db_host":    "my-cluster.abc123.us-east-1.redshift.amazonaws.com",
			"db_port":    "5439",
			"db_user":    "IAMR:warden-role",
		},
	}
	grant := dbaccess.Grant{"db_name": "analytics"}

	out := formatAccess(cred, grant, "workload-a")
	assert.Equal(t,
		"host=my-cluster.abc123.us-east-1.redshift.amazonaws.com port=5439 dbname=analytics user=IAMR:warden-role password='secret-token' sslmode=require application_name=workload-a",
		out["connection_string"],
	)
}

func TestFormatAccess_PasswordSingleQuoted(t *testing.T) {
	// Single-quoted password sidesteps special characters that would
	// otherwise need escaping in libpq DSN format.
	cred := &credential.Credential{
		Data: map[string]string{
			"auth_token": "abc/def+ghi=jkl",
			"db_host":    "h",
			"db_port":    "5439",
			"db_user":    "u",
		},
	}
	grant := dbaccess.Grant{"db_name": "db"}

	out := formatAccess(cred, grant, "w")
	assert.Contains(t, out["connection_string"].(string), "password='abc/def+ghi=jkl'")
}

func TestFormatAccess_EmptyPrincipal(t *testing.T) {
	cred := &credential.Credential{
		Data: map[string]string{
			"auth_token": "t",
			"db_host":    "h",
			"db_port":    "5439",
			"db_user":    "u",
		},
	}
	grant := dbaccess.Grant{"db_name": "db"}

	out := formatAccess(cred, grant, "")
	assert.Contains(t, out["connection_string"].(string), "application_name=")
}

func TestFormatAccess_MissingFieldsDoNotPanic(t *testing.T) {
	cred := &credential.Credential{Data: map[string]string{}}
	grant := dbaccess.Grant{}
	assert.NotPanics(t, func() {
		_ = formatAccess(cred, grant, "")
	})
}
