package types

import (
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDBAuthTokenCredType_Metadata(t *testing.T) {
	ct := NewDBAuthTokenCredType()
	meta := ct.Metadata()
	assert.Equal(t, credential.TypeDBAuthToken, meta.Name)
	assert.Equal(t, credential.CategoryDatabase, meta.Category)
	assert.Equal(t, 15*time.Minute, meta.DefaultTTL)
}

func TestDBAuthTokenCredType_Parse(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	rawData := map[string]interface{}{
		"auth_token": "my-iam-token-xyz",
		"db_host":    "mydb.abc123.us-east-1.rds.amazonaws.com",
		"db_port":    "5432",
		"db_user":    "app_readonly",
		"db_engine":  "postgres",
		"token_type": "rds_iam",
		"region":     "us-east-1",
	}

	cred, err := ct.Parse(rawData, 15*time.Minute, "")
	require.NoError(t, err)

	assert.Equal(t, credential.TypeDBAuthToken, cred.Type)
	assert.Equal(t, credential.CategoryDatabase, cred.Category)
	assert.Equal(t, 15*time.Minute, cred.LeaseTTL)
	assert.False(t, cred.Revocable)
	assert.Equal(t, "my-iam-token-xyz", cred.Data["auth_token"])
	assert.Equal(t, "mydb.abc123.us-east-1.rds.amazonaws.com", cred.Data["db_host"])
	assert.Equal(t, "5432", cred.Data["db_port"])
	assert.Equal(t, "app_readonly", cred.Data["db_user"])
	assert.Equal(t, "postgres", cred.Data["db_engine"])
	assert.Equal(t, "rds_iam", cred.Data["token_type"])
	assert.Equal(t, "us-east-1", cred.Data["region"])
}

func TestDBAuthTokenCredType_Parse_MissingToken(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	rawData := map[string]interface{}{
		"db_host": "mydb.rds.amazonaws.com",
	}

	_, err := ct.Parse(rawData, 15*time.Minute, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth_token")
}

func TestDBAuthTokenCredType_ValidateConfig_RDS(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method": "rds_iam_token",
		"db_user":     "app_readonly",
		"db_endpoint": "mydb.abc123.us-east-1.rds.amazonaws.com",
		"db_engine":   "postgres",
		"region":      "us-east-1",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.NoError(t, err)
}

func TestDBAuthTokenCredType_ValidateConfig_RDS_WrongSource(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method": "rds_iam_token",
		"db_user":     "app_readonly",
		"db_endpoint": "mydb.rds.amazonaws.com",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeGCP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aws source")
}

func TestDBAuthTokenCredType_ValidateConfig_RDS_MissingEndpoint(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method": "rds_iam_token",
		"db_user":     "app_readonly",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db_endpoint")
}

func TestDBAuthTokenCredType_ValidateConfig_CloudSQL(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":            "cloud_sql_iam_token",
		"db_user":                "db-reader@myproject.iam",
		"target_service_account": "db-reader@myproject.iam.gserviceaccount.com",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeGCP)
	assert.NoError(t, err)
}

func TestDBAuthTokenCredType_ValidateConfig_CloudSQL_WrongSource(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":            "cloud_sql_iam_token",
		"db_user":                "db-reader",
		"target_service_account": "sa@proj.iam.gserviceaccount.com",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "gcp source")
}

func TestDBAuthTokenCredType_ValidateConfig_Azure(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method": "azure_db_iam_token",
		"db_user":     "app-identity@mydb",
		"db_host":     "mydb.postgres.database.azure.com",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAzure)
	assert.NoError(t, err)
}

func TestDBAuthTokenCredType_ValidateConfig_Azure_MissingHost(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method": "azure_db_iam_token",
		"db_user":     "app-identity",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAzure)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db_host")
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_Provisioned(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":        "redshift_iam_token",
		"db_endpoint":        "my-cluster.abc123.us-east-1.redshift.amazonaws.com",
		"cluster_identifier": "my-cluster",
		"region":             "us-east-1",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.NoError(t, err)
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_Serverless(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":    "redshift_iam_token",
		"db_endpoint":    "my-wg.123456789.us-east-1.redshift-serverless.amazonaws.com",
		"workgroup_name": "my-wg",
		"region":         "us-east-1",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.NoError(t, err)
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_WithDuration(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":        "redshift_iam_token",
		"db_endpoint":        "my-cluster.example.redshift.amazonaws.com",
		"cluster_identifier": "my-cluster",
		"duration_seconds":   "3600",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.NoError(t, err)
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_WrongSource(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":        "redshift_iam_token",
		"db_endpoint":        "x",
		"cluster_identifier": "x",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeGCP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aws source")
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_MissingEndpoint(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":        "redshift_iam_token",
		"cluster_identifier": "my-cluster",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db_endpoint")
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_NoClusterOrWorkgroup(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method": "redshift_iam_token",
		"db_endpoint": "x",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cluster_identifier")
	assert.Contains(t, err.Error(), "workgroup_name")
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_BothClusterAndWorkgroup(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":        "redshift_iam_token",
		"db_endpoint":        "x",
		"cluster_identifier": "my-cluster",
		"workgroup_name":     "my-wg",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one")
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_DurationOutOfRange(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	for _, d := range []string{"0", "100", "899", "3601", "10000"} {
		t.Run("duration="+d, func(t *testing.T) {
			config := map[string]string{
				"mint_method":        "redshift_iam_token",
				"db_endpoint":        "x",
				"cluster_identifier": "my-cluster",
				"duration_seconds":   d,
			}
			err := ct.ValidateConfig(config, credential.SourceTypeAWS)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "duration_seconds")
		})
	}
}

func TestDBAuthTokenCredType_ValidateConfig_Redshift_InvalidDuration(t *testing.T) {
	ct := NewDBAuthTokenCredType()

	config := map[string]string{
		"mint_method":        "redshift_iam_token",
		"db_endpoint":        "x",
		"cluster_identifier": "my-cluster",
		"duration_seconds":   "not-a-number",
	}

	err := ct.ValidateConfig(config, credential.SourceTypeAWS)
	assert.Error(t, err)
}

func TestDBAuthTokenCredType_RequiresSpecRotation(t *testing.T) {
	ct := NewDBAuthTokenCredType()
	assert.False(t, ct.RequiresSpecRotation())
}

func TestDBAuthTokenCredType_SensitiveConfigFields(t *testing.T) {
	ct := NewDBAuthTokenCredType()
	assert.Nil(t, ct.SensitiveConfigFields())
}
