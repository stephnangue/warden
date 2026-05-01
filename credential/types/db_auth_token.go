package types

import (
	"fmt"
	"strconv"
	"time"

	"github.com/stephnangue/warden/credential"
)

// DBAuthTokenCredType handles database IAM authentication tokens for cloud-native databases.
// Supports RDS IAM auth (AWS), Cloud SQL IAM auth (GCP), and Azure AD database auth.
type DBAuthTokenCredType struct {
	*BaseTokenType
}

// NewDBAuthTokenCredType creates a new database auth token credential type
func NewDBAuthTokenCredType() *DBAuthTokenCredType {
	return &DBAuthTokenCredType{
		BaseTokenType: &BaseTokenType{
			TypeMetadata: credential.TypeMetadata{
				Name:        credential.TypeDBAuthToken,
				Category:    credential.CategoryDatabase,
				Description: "Database IAM authentication token for cloud-native databases",
				DefaultTTL:  15 * time.Minute, // RDS tokens valid for 15 min; GCP/Azure ~1 hour
			},
			FieldConfig: TokenFieldConfig{
				PrimaryField:      "auth_token",
				AlternativeFields: []string{},
				OptionalFields: []string{
					"db_host", "db_port", "db_user", "db_engine",
					"token_type", "region", "instance_connection_name",
					"deployment",
				},
				FieldSchemas: map[string]*credential.CredentialFieldSchema{
					"auth_token": {
						Description: "Database IAM auth token (used as password)",
						Sensitive:   true,
					},
					"db_host": {
						Description: "Database hostname",
						Sensitive:   false,
					},
					"db_port": {
						Description: "Database port",
						Sensitive:   false,
					},
					"db_user": {
						Description: "Database user",
						Sensitive:   false,
					},
					"db_engine": {
						Description: "Database engine (postgres, mysql)",
						Sensitive:   false,
					},
					"token_type": {
						Description: "Token type (rds_iam, gcp_oauth2, azure_ad)",
						Sensitive:   false,
					},
					"region": {
						Description: "Cloud region",
						Sensitive:   false,
					},
					"instance_connection_name": {
						Description: "Cloud SQL instance connection name",
						Sensitive:   false,
					},
				},
			},
			Revocable: false, // All DB IAM tokens expire naturally
		},
	}
}

// ConfigSchema returns the declarative schema for database auth token credential config
func (t *DBAuthTokenCredType) ConfigSchema() []*credential.FieldValidator {
	return []*credential.FieldValidator{
		credential.StringField("mint_method").
			OneOf("rds_iam_token", "redshift_iam_token", "cloud_sql_iam_token", "azure_db_iam_token").
			Describe("Method for minting database IAM auth tokens").
			Example("rds_iam_token"),

		// db_user is required for rds_iam_token / cloud_sql_iam_token / azure_db_iam_token
		// (enforced in ValidateConfig). Not required for redshift_iam_token because the
		// Redshift API returns the database user mapped from the IAM identity.
		credential.StringField("db_user").
			Describe("Database user to authenticate as").
			Example("app_readonly"),

		credential.StringField("db_endpoint").
			Describe("Database endpoint hostname (required for rds_iam_token and redshift_iam_token)").
			Example("mydb.abc123.us-east-1.rds.amazonaws.com"),

		credential.StringField("db_host").
			Describe("Database hostname (required for azure_db_iam_token)").
			Example("mydb.postgres.database.azure.com"),

		credential.StringField("db_port").
			Describe("Database port (defaults based on engine: postgres=5432, mysql=3306, redshift=5439)").
			Example("5432"),

		credential.StringField("db_engine").
			OneOf("postgres", "mysql").
			Describe("Database engine type").
			Example("postgres"),

		credential.StringField("region").
			Describe("Cloud region (defaults to source region for AWS)").
			Example("us-east-1"),

		credential.StringField("role_arn").
			Describe("AWS IAM role ARN for cross-account access (rds_iam_token)").
			Example("arn:aws:iam::123456789:role/db-access"),

		credential.StringField("target_service_account").
			Describe("GCP service account to impersonate (required for cloud_sql_iam_token)").
			Example("db-reader@myproject.iam.gserviceaccount.com"),

		credential.StringField("instance_connection_name").
			Describe("Cloud SQL instance connection name (optional metadata for cloud_sql_iam_token)").
			Example("myproject:us-central1:mydb"),

		credential.StringField("resource_uri").
			Describe("Azure AD resource URI override (azure_db_iam_token)").
			Example("https://ossrdbms-aad.database.windows.net/"),

		credential.StringField("cluster_identifier").
			Describe("Redshift provisioned cluster identifier (redshift_iam_token; mutually exclusive with workgroup_name)").
			Example("my-redshift-cluster"),

		credential.StringField("workgroup_name").
			Describe("Redshift Serverless workgroup name (redshift_iam_token; mutually exclusive with cluster_identifier)").
			Example("my-workgroup"),

		credential.StringField("db_name").
			Describe("Database name passed to AWS for IAM scoping (redshift_iam_token)").
			Example("analytics"),

		credential.IntField("duration_seconds").
			Describe("Token TTL in seconds for redshift_iam_token, range 900-3600. Default 900.").
			Example("900"),
	}
}

// ValidateConfig validates the config for a database auth token credential spec.
// Cross-validates mint_method against source type and required fields.
func (t *DBAuthTokenCredType) ValidateConfig(config map[string]string, sourceType string) error {
	schema := t.ConfigSchema()
	if err := credential.ValidateSchema(config, schema...); err != nil {
		return err
	}

	mintMethod := config["mint_method"]
	switch mintMethod {
	case "rds_iam_token":
		if sourceType != credential.SourceTypeAWS {
			return fmt.Errorf("rds_iam_token requires an aws source, got: %s", sourceType)
		}
		if config["db_endpoint"] == "" {
			return fmt.Errorf("rds_iam_token requires db_endpoint")
		}
		if config["db_user"] == "" {
			return fmt.Errorf("rds_iam_token requires db_user")
		}
	case "redshift_iam_token":
		if sourceType != credential.SourceTypeAWS {
			return fmt.Errorf("redshift_iam_token requires an aws source, got: %s", sourceType)
		}
		if config["db_endpoint"] == "" {
			return fmt.Errorf("redshift_iam_token requires db_endpoint")
		}
		hasCluster := config["cluster_identifier"] != ""
		hasWorkgroup := config["workgroup_name"] != ""
		if !hasCluster && !hasWorkgroup {
			return fmt.Errorf("redshift_iam_token requires either cluster_identifier (provisioned) or workgroup_name (serverless)")
		}
		if hasCluster && hasWorkgroup {
			return fmt.Errorf("redshift_iam_token requires exactly one of cluster_identifier or workgroup_name, not both")
		}
		if d := config["duration_seconds"]; d != "" {
			n, err := strconv.Atoi(d)
			if err != nil {
				return fmt.Errorf("duration_seconds must be an integer: %w", err)
			}
			if n < 900 || n > 3600 {
				return fmt.Errorf("duration_seconds must be between 900 and 3600, got %d", n)
			}
		}
	case "cloud_sql_iam_token":
		if sourceType != credential.SourceTypeGCP {
			return fmt.Errorf("cloud_sql_iam_token requires a gcp source, got: %s", sourceType)
		}
		if config["target_service_account"] == "" {
			return fmt.Errorf("cloud_sql_iam_token requires target_service_account")
		}
		if config["db_user"] == "" {
			return fmt.Errorf("cloud_sql_iam_token requires db_user")
		}
	case "azure_db_iam_token":
		if sourceType != credential.SourceTypeAzure {
			return fmt.Errorf("azure_db_iam_token requires an azure source, got: %s", sourceType)
		}
		if config["db_host"] == "" {
			return fmt.Errorf("azure_db_iam_token requires db_host")
		}
		if config["db_user"] == "" {
			return fmt.Errorf("azure_db_iam_token requires db_user")
		}
	default:
		return fmt.Errorf("unsupported mint_method: %s", mintMethod)
	}

	return nil
}

// RequiresSpecRotation returns false — DB auth tokens are short-lived and don't need spec rotation.
func (t *DBAuthTokenCredType) RequiresSpecRotation() bool {
	return false
}

// SensitiveConfigFields returns spec config keys that should be masked in output
func (t *DBAuthTokenCredType) SensitiveConfigFields() []string {
	return nil
}
