package rds

import (
	"testing"

	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/provider/sdk/dbaccess"
	"github.com/stretchr/testify/assert"
)

// Standard backend behavior (Factory wiring, config CRUD, grant CRUD,
// transparent mode, access-endpoint plumbing, role query parameter) is
// covered by provider/sdk/dbaccess/provider_test.go against the shared
// framework. These tests cover only the RDS-specific formatter, including
// engine-specific DSN shapes and MySQL token escaping.

func baseCred() *credential.Credential {
	return &credential.Credential{
		Data: map[string]string{
			"auth_token": "my-token",
			"db_host":    "mydb.rds.amazonaws.com",
			"db_port":    "5432",
			"db_user":    "app_user",
			"db_engine":  "postgres",
		},
	}
}

func TestFormatAccess_Postgres(t *testing.T) {
	grant := dbaccess.Grant{"db_name": "myapp", "db_engine": "postgres"}
	out := formatAccess(baseCred(), grant, "workload-a")
	assert.Equal(t,
		"host=mydb.rds.amazonaws.com port=5432 dbname=myapp user=app_user password=my-token sslmode=require application_name=workload-a",
		out["connection_string"],
	)
}

func TestFormatAccess_MySQL(t *testing.T) {
	grant := dbaccess.Grant{"db_name": "myapp", "db_engine": "mysql"}
	out := formatAccess(baseCred(), grant, "workload-b")
	assert.Equal(t,
		"app_user:my-token@tcp(mydb.rds.amazonaws.com:5432)/myapp?tls=true&connectionAttributes=program_name:workload-b",
		out["connection_string"],
	)
}

func TestFormatAccess_EngineFallbackFromCredential(t *testing.T) {
	// When the grant doesn't specify db_engine, the formatter falls back to
	// the engine carried on the minted credential.
	grant := dbaccess.Grant{"db_name": "myapp"}
	out := formatAccess(baseCred(), grant, "workload-d")
	connStr := out["connection_string"].(string)
	assert.Contains(t, connStr, "host=")
	assert.Contains(t, connStr, "sslmode=require")
}

func TestFormatAccess_MySQLTokenEscaped(t *testing.T) {
	cred := &credential.Credential{
		Data: map[string]string{
			"auth_token": "token/with+special=chars&more",
			"db_host":    "h",
			"db_port":    "3306",
			"db_user":    "u",
			"db_engine":  "mysql",
		},
	}
	grant := dbaccess.Grant{"db_name": "db", "db_engine": "mysql"}
	out := formatAccess(cred, grant, "w")
	connStr := out["connection_string"].(string)
	assert.NotContains(t, connStr, "token/with+special")
	assert.Contains(t, connStr, "token%2Fwith%2Bspecial%3Dchars%26more")
}

func TestFormatAccess_LeaseDuration(t *testing.T) {
	cred := baseCred()
	cred.LeaseTTL = 0
	grant := dbaccess.Grant{"db_name": "myapp", "db_engine": "postgres"}
	out := formatAccess(cred, grant, "w")
	assert.Equal(t, 0, out["lease_duration"])
}
