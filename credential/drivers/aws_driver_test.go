package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/types"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// primeClients gives a hand-built driver a usable client generation without the
// network probe, standing in for the Create-time authenticate these tests skip.
func primeClients(d *AWSDriver) {
	d.authMu.Lock()
	defer d.authMu.Unlock()
	d.baseCredsVerified = true
	d.buildClientsLocked(d.baseCreds)
}

func TestAWSDriverFactory_Type(t *testing.T) {
	factory := &AWSDriverFactory{}
	assert.Equal(t, credential.SourceTypeAWS, factory.Type())
}

func TestAWSDriverFactory_SensitiveConfigFields(t *testing.T) {
	factory := &AWSDriverFactory{}
	fields := factory.SensitiveConfigFields()
	assert.Contains(t, fields, "secret_access_key")
}

func TestAWSDriverFactory_ValidateConfig(t *testing.T) {
	factory := &AWSDriverFactory{}

	tests := []struct {
		name    string
		config  credential.Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config",
			config: credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
			}),
			wantErr: false,
		},
		{
			name: "valid config with assume_role_arn",
			config: credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
				"assume_role_arn":   "arn:aws:iam::123456789012:role/test-role",
				"external_id":       "ext-123",
				"session_name":      "my-session",
				"session_duration":  "2h",
			}),
			wantErr: false,
		},
		{
			name: "valid config with endpoint overrides",
			config: credential.NewConfig(map[string]string{
				"access_key_id":           "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key":       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":                  "us-east-1",
				"sts_endpoint":            "https://sts.us-east-1.amazonaws.com",
				"secretsmanager_endpoint": "https://secretsmanager.us-east-1.amazonaws.com",
			}),
			wantErr: false,
		},
		{
			name: "endpoint overrides on a federation source",
			config: credential.NewConfig(map[string]string{
				"auth_method":             "oidc_federation",
				"region":                  "us-east-1",
				"sts_endpoint":            "https://sts.us-east-1.amazonaws.com",
				"secretsmanager_endpoint": "https://secretsmanager.us-east-1.amazonaws.com",
			}),
			wantErr: false,
		},
		{
			name: "missing access_key_id",
			config: credential.NewConfig(map[string]string{
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
			}),
			wantErr: true,
			errMsg:  "access_key_id",
		},
		{
			name: "missing secret_access_key",
			config: credential.NewConfig(map[string]string{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				"region":        "us-east-1",
			}),
			wantErr: true,
			errMsg:  "secret_access_key",
		},
		{
			name: "missing region",
			config: credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			}),
			wantErr: true,
			errMsg:  "region",
		},
		{
			name: "invalid session_duration",
			config: credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
				"session_duration":  "invalid",
			}),
			wantErr: true,
			errMsg:  "session_duration",
		},
		{
			name:    "oidc_federation valid without keys",
			config:  credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"}),
			wantErr: false,
		},
		{
			name:    "oidc_federation rejects static keys",
			config:  credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1", "access_key_id": "AKIA..."}),
			wantErr: true,
			errMsg:  "must not be set for auth_method=oidc_federation",
		},
		{
			name:    "oidc_federation rejects assume_role_arn",
			config:  credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1", "assume_role_arn": "arn:aws:iam::1:role/x"}),
			wantErr: true,
			errMsg:  "assume_role_arn is not supported",
		},
		{
			name:    "invalid auth_method",
			config:  credential.NewConfig(map[string]string{"auth_method": "bogus", "region": "us-east-1"}),
			wantErr: true,
			errMsg:  "auth_method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := factory.ValidateConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAWSDriver_Type(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{}),
		},
	}
	assert.Equal(t, credential.SourceTypeAWS, driver.Type())
}

func TestAWSDriver_Cleanup(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{}),
		},
	}
	err := driver.Cleanup(context.TODO())
	assert.NoError(t, err)
}

func TestAWSDriver_Revoke_STS(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{}),
		},
	}

	// STS credentials can't be revoked — should return nil
	err := driver.Revoke(context.TODO(), "sts:ASIA1234567890ABCDEF")
	assert.NoError(t, err)

	// Empty lease ID — should return nil
	err = driver.Revoke(context.TODO(), "")
	assert.NoError(t, err)
}

func TestAWSDriver_SupportsRotation(t *testing.T) {
	tests := []struct {
		name       string
		accessKey  string
		wantResult bool
	}{
		{
			name:       "permanent IAM key supports rotation",
			accessKey:  "AKIAIOSFODNN7EXAMPLE",
			wantResult: true,
		},
		{
			name:       "STS temporary key does not support rotation",
			accessKey:  "ASIAIOSFODNN7EXAMPLE",
			wantResult: false,
		},
		{
			name:       "empty key does not support rotation",
			accessKey:  "",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver := &AWSDriver{
				credSource: &credential.CredSource{
					Type: credential.SourceTypeAWS,
					Config: credential.NewConfig(map[string]string{
						"access_key_id": tt.accessKey,
					}),
				},
			}
			assert.Equal(t, tt.wantResult, driver.SupportsRotation())
		})
	}
}

func TestAccountIDFromARN(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{
			name:     "assumed role ARN",
			arn:      "arn:aws:sts::123456789012:assumed-role/app-backend/warden-session",
			expected: "123456789012",
		},
		{
			name:     "iam role ARN",
			arn:      "arn:aws:iam::123456789012:role/app-backend",
			expected: "123456789012",
		},
		{
			name:     "too few segments",
			arn:      "arn:aws:iam::123456789012",
			expected: "",
		},
		{
			name:     "empty",
			arn:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, accountIDFromARN(tt.arn))
		})
	}
}

func TestAWSDriver_MintCredential_InvalidMethod(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			}),
		},
		region: "us-east-1",
	}
	// Build clients so authenticate doesn't fail (no assume_role_arn)
	primeClients(driver)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeAWSAccessKeys,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "invalid",
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

func TestAWSDriver_MintCredential_TTLBelowMinimum(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			}),
		},
		region: "us-east-1",
	}
	primeClients(driver)

	spec := &credential.CredSpec{
		Name:   "test-spec",
		Type:   credential.TypeAWSAccessKeys,
		MinTTL: 2 * time.Hour,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "sts_assume_role",
			"role_arn":    "arn:aws:iam::123456789012:role/test-role",
			"ttl":         "30m", // Below MinTTL of 2h
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestAWSDriver_MintCredential_TTLExceedsMaximum(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			}),
		},
		region: "us-east-1",
	}
	primeClients(driver)

	spec := &credential.CredSpec{
		Name:   "test-spec",
		Type:   credential.TypeAWSAccessKeys,
		MaxTTL: 1 * time.Hour,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "sts_assume_role",
			"role_arn":    "arn:aws:iam::123456789012:role/test-role",
			"ttl":         "4h", // Above MaxTTL of 1h
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestAWSDriver_Type_ViaFactory(t *testing.T) {
	// Don't call Create (it tries to authenticate with AWS).
	// Just test Type() on a manually constructed driver.
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{}),
		},
	}
	assert.Equal(t, credential.SourceTypeAWS, driver.Type())
}

// =============================================================================
// AWSDriver redshift_iam_token tests
// =============================================================================

func TestAWSDriverFactory_InferCredentialType_Redshift(t *testing.T) {
	factory := &AWSDriverFactory{}

	credType, err := factory.InferCredentialType(credential.NewConfig(map[string]string{
		"mint_method": "redshift_iam_token",
	}))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeDBAuthToken, credType)
}

// TestAWSDriverFactory_InferCredentialType_SecretsManager covers the shape selector:
// a Secrets Manager secret defaults to AWS access keys, and credential_type selects a
// different stored-secret shape.
func TestAWSDriverFactory_InferCredentialType_SecretsManager(t *testing.T) {
	factory := &AWSDriverFactory{}

	cases := []struct {
		name     string
		credType string
		want     string
		wantErr  bool
	}{
		{name: "default is aws access keys", credType: "", want: credential.TypeAWSAccessKeys},
		{name: "explicit aws access keys", credType: credential.TypeAWSAccessKeys, want: credential.TypeAWSAccessKeys},
		{name: "api key shape", credType: credential.TypeAPIKey, want: credential.TypeAPIKey},
		{name: "unsupported shape rejected", credType: "gitlab_access_token", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := map[string]string{"mint_method": "secrets_manager"}
			if tc.credType != "" {
				cfg["credential_type"] = tc.credType
			}
			got, err := factory.InferCredentialType(credential.NewConfig(cfg))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	// credential_type is meaningful only for secrets_manager; using it elsewhere is
	// an explicit error, not a silent fallback to aws_access_keys.
	t.Run("credential_type rejected for non-secrets_manager mint", func(t *testing.T) {
		_, err := factory.InferCredentialType(credential.NewConfig(map[string]string{
			"mint_method":     "sts_assume_role",
			"credential_type": credential.TypeAPIKey,
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only valid with mint_method=secrets_manager")
	})
}

// newRedshiftTestDriver creates a driver with verified base creds and built clients,
// suitable for exercising mintViaRedshiftIAMToken's validation paths.
// It does NOT make real AWS calls — tests must short-circuit before the SDK call.
func newRedshiftTestDriver(t *testing.T) *AWSDriver {
	t.Helper()
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			}),
		},
		region: "us-east-1",
	}
	primeClients(driver)
	return driver
}

func TestAWSDriver_MintCredential_RedshiftIAMToken_MissingEndpoint(t *testing.T) {
	driver := newRedshiftTestDriver(t)

	spec := &credential.CredSpec{
		Name: "redshift-test",
		Type: credential.TypeDBAuthToken,
		Config: credential.NewConfig(map[string]string{
			"mint_method":        "redshift_iam_token",
			"cluster_identifier": "my-cluster",
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db_endpoint")
}

func TestAWSDriver_MintCredential_RedshiftIAMToken_NoClusterOrWorkgroup(t *testing.T) {
	driver := newRedshiftTestDriver(t)

	spec := &credential.CredSpec{
		Name: "redshift-test",
		Type: credential.TypeDBAuthToken,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "redshift_iam_token",
			"db_endpoint": "my-cluster.redshift.amazonaws.com",
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cluster_identifier")
	assert.Contains(t, err.Error(), "workgroup_name")
}

func TestAWSDriver_MintCredential_RedshiftIAMToken_BothClusterAndWorkgroup(t *testing.T) {
	driver := newRedshiftTestDriver(t)

	spec := &credential.CredSpec{
		Name: "redshift-test",
		Type: credential.TypeDBAuthToken,
		Config: credential.NewConfig(map[string]string{
			"mint_method":        "redshift_iam_token",
			"db_endpoint":        "x",
			"cluster_identifier": "my-cluster",
			"workgroup_name":     "my-wg",
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one")
}

func TestAWSDriver_MintCredential_RedshiftIAMToken_DurationOutOfRange(t *testing.T) {
	driver := newRedshiftTestDriver(t)

	for _, d := range []string{"100", "899", "3601", "100000"} {
		t.Run("duration="+d, func(t *testing.T) {
			spec := &credential.CredSpec{
				Name: "redshift-test",
				Type: credential.TypeDBAuthToken,
				Config: credential.NewConfig(map[string]string{
					"mint_method":        "redshift_iam_token",
					"db_endpoint":        "x",
					"cluster_identifier": "my-cluster",
					"duration_seconds":   d,
				}),
			}
			_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "duration_seconds")
		})
	}
}

func TestAWSDriver_MintCredential_UnsupportedMethodMessage_IncludesRedshift(t *testing.T) {
	// Sanity check: the error message for unknown mint methods should advertise
	// the new redshift_iam_token option so users see it in the surfaced error.
	driver := newRedshiftTestDriver(t)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeAWSAccessKeys,
		Config: credential.NewConfig(map[string]string{
			"mint_method": "definitely-not-real",
		}),
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redshift_iam_token")
}

// =============================================================================
// AWS Workload Identity Federation (AssumeRoleWithWebIdentity)
// =============================================================================

// TestAWSDriver_Create_WIF_Keyless verifies an oidc_federation source is
// constructed with no IAM keys and without an eager credential probe (no network).
func TestAWSDriver_Create_WIF_Keyless(t *testing.T) {
	factory := &AWSDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := factory.Create(credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"}), log)
	require.NoError(t, err)
	require.NotNil(t, drv)
	awsDrv := drv.(*AWSDriver)
	assert.NotNil(t, awsDrv.anonSTSClient, "oidc_federation source must build the anonymous STS client")
}

// TestAWSDriver_MintGuards covers the fail-closed routing between the exchange
// and non-exchange paths.
func TestAWSDriver_MintGuards(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})

	// An oidc_federation source reached via the non-exchange path (the spec lacks
	// subject_token_source) must fail clearly, not fall into authenticate() with
	// empty keys.
	wifDrv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"})},
		logger:     log,
	}
	for _, mm := range []string{"secrets_manager", "sts_assume_role"} {
		_, _, _, _, err := wifDrv.MintCredential(context.TODO(), &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": mm})})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires subject_token_source on the spec (warden_identity or agent_identity)")
	}
}

// TestAWSDriver_MintCredentialWithExchange_Guards covers the exchange-path guards
// before any network call.
func TestAWSDriver_MintCredentialWithExchange_Guards(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"})},
		logger:     log,
	}
	roleSpec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "sts_assume_role", "role_arn": "arn:aws:iam::1:role/x"})}
	verified := &credential.ExchangeInputs{SubjectToken: "eyJ"}

	// A static source must not reach the federation path.
	staticDrv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{"auth_method": "static"})},
		logger:     log,
	}
	_, _, _, _, err := staticDrv.MintCredentialWithExchange(context.TODO(), roleSpec, verified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method=oidc_federation")

	// A mint_method with no federation support is rejected before any STS call.
	_, _, _, _, err = drv.MintCredentialWithExchange(context.TODO(), &credential.CredSpec{Config: credential.NewConfig(map[string]string{"mint_method": "rds_iam_token"})}, verified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported over auth_method=oidc_federation")

	// Missing subject.
	_, _, _, _, err = drv.MintCredentialWithExchange(context.TODO(), roleSpec, &credential.ExchangeInputs{})
	require.Error(t, err)

	// For sts_assume_role, the requested TTL is bound-checked before any STS call.
	boundedSpec := &credential.CredSpec{Name: "s", Config: credential.NewConfig(map[string]string{"mint_method": "sts_assume_role", "role_arn": "arn:aws:iam::1:role/x", "ttl": "2h"}), MaxTTL: time.Hour}
	_, _, _, _, err = drv.MintCredentialWithExchange(context.TODO(), boundedSpec, verified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

// TestAWSDriver_WebIdentity_HappyPath drives mint_method=sts_assume_role over a keyless
// (oidc_federation) source against a mocked STS endpoint, asserting the assertion is
// forwarded as WebIdentityToken and the assumed-role credentials are surfaced.
func TestAWSDriver_WebIdentity_HappyPath(t *testing.T) {
	var gotToken, gotAction string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.Form.Get("WebIdentityToken")
		gotAction = r.Form.Get("Action")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretexample</SecretAccessKey>
      <SessionToken>tokenexample</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/App/warden-wid</Arn>
      <AssumedRoleId>AROAEXAMPLE:warden-wid</AssumedRoleId>
    </AssumedRoleUser>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"})},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
	}
	spec := &credential.CredSpec{Name: "wid", Config: credential.NewConfig(map[string]string{
		"mint_method": "sts_assume_role",
		"role_arn":    "arn:aws:iam::123456789012:role/App",
		"ttl":         "15m",
	})}
	inputs := &credential.ExchangeInputs{
		SubjectToken:     "eyJ.warden.assertion",
		SubjectTokenType: credential.TokenTypeJWT,
	}

	rawData, metadata, ttl, leaseID, err := drv.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "AssumeRoleWithWebIdentity", gotAction)
	assert.Equal(t, "eyJ.warden.assertion", gotToken, "the Warden assertion must be sent as WebIdentityToken")
	assert.Equal(t, "ASIAEXAMPLE", rawData["access_key_id"])
	assert.Equal(t, "secretexample", rawData["secret_access_key"])
	assert.Equal(t, "tokenexample", rawData["session_token"])
	assert.Equal(t, "arn:aws:sts::123456789012:assumed-role/App/warden-wid", metadata["assumed_role_arn"])
	assert.Equal(t, "123456789012", metadata["account_id"])
	assert.Equal(t, "sts:ASIAEXAMPLE", leaseID)
	assert.Greater(t, ttl, time.Duration(0))
}

// TestAWSDriver_WebIdentity_ForwardedSubject_HappyPath drives the agent_identity
// federation topology: the subject is the caller's inbound JWT that Warden forwards
// untouched (not a Warden-minted assertion), so ResolveSubjectToken and SubjectCacheIdentity
// are unset. The driver forwards any subject it is given the same way, so this must reach
// STS and forward the token verbatim.
func TestAWSDriver_WebIdentity_ForwardedSubject_HappyPath(t *testing.T) {
	var gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.Form.Get("WebIdentityToken")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretexample</SecretAccessKey>
      <SessionToken>tokenexample</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/App/warden-wid</Arn>
      <AssumedRoleId>AROAEXAMPLE:warden-wid</AssumedRoleId>
    </AssumedRoleUser>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"})},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
	}
	spec := &credential.CredSpec{Name: "wid", Config: credential.NewConfig(map[string]string{
		"mint_method": "sts_assume_role",
		"role_arn":    "arn:aws:iam::123456789012:role/App",
		"ttl":         "15m",
	})}
	// A forwarded inbound JWT: eager, with no ResolveSubjectToken and no
	// SubjectCacheIdentity (the token is stable, so it keys the cache itself).
	inputs := &credential.ExchangeInputs{
		SubjectToken:     "eyJ.inbound.idp.jwt",
		SubjectTokenType: credential.TokenTypeJWT,
	}

	rawData, _, _, _, err := drv.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "eyJ.inbound.idp.jwt", gotToken, "the forwarded inbound JWT must be sent as WebIdentityToken verbatim")
	assert.Equal(t, "ASIAEXAMPLE", rawData["access_key_id"])
}

// TestAWSDriver_SecretsManager_WebIdentity_HappyPath drives the keyless two-step:
// federate the assertion for short-lived role credentials, then read a Secrets Manager
// secret with those credentials.
func TestAWSDriver_SecretsManager_WebIdentity_HappyPath(t *testing.T) {
	var gotToken, gotDuration string
	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.Form.Get("WebIdentityToken")
		gotDuration = r.Form.Get("DurationSeconds")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretexample</SecretAccessKey>
      <SessionToken>tokenexample</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	defer stsSrv.Close()

	// The stored secret holds AWS IAM keys — that is the shape mint_method=secrets_manager
	// yields (the credential type is aws_access_keys), whether static or keyless.
	var smTarget, smAuth string
	smSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		smTarget = r.Header.Get("X-Amz-Target")
		smAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Name":"prod/app/keys","SecretString":"{\"access_key_id\":\"AKIASTOREDEXAMPLE\",\"secret_access_key\":\"0123456789012345678901234567890123456789\"}"}`))
	}))
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"})},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(stsSrv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
		smBaseEndpoint: smSrv.URL,
	}
	spec := &credential.CredSpec{Name: "app", Config: credential.NewConfig(map[string]string{
		"mint_method": "secrets_manager",
		"secret_id":   "prod/app/keys",
		"role_arn":    "arn:aws:iam::123456789012:role/WardenSecretsReader",
	})}
	inputs := &credential.ExchangeInputs{
		SubjectToken:     "eyJ.warden.assertion",
		SubjectTokenType: credential.TokenTypeJWT,
	}

	rawData, metadata, ttl, leaseID, err := drv.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "eyJ.warden.assertion", gotToken, "the Warden assertion must be sent as WebIdentityToken")
	// The transient fetch session is the fixed 15m minimum, not the secret's TTL.
	assert.Equal(t, "900", gotDuration, "the federated fetch must request a fixed 15m session")
	assert.Contains(t, smTarget, "GetSecretValue", "the second call must hit Secrets Manager")
	// The Secrets Manager call must be signed with the freshly federated temp creds
	// (their access key id appears in the SigV4 Credential= scope).
	assert.Contains(t, smAuth, "ASIAEXAMPLE", "the secret read must use the federated credentials")
	assert.Equal(t, "AKIASTOREDEXAMPLE", rawData["access_key_id"])
	assert.Equal(t, "0123456789012345678901234567890123456789", rawData["secret_access_key"])
	// A fetched secret is static: no metadata, no lease.
	assert.Nil(t, metadata)
	assert.Equal(t, time.Duration(0), ttl)
	assert.Equal(t, "", leaseID)
}

// TestAWSDriver_SecretsManager_APIKey_RoundTrip proves the hvault-mirror pattern end to
// end: the keyless secrets_manager fetch is shape-agnostic, and the same fetched blob is
// parsed by the api_key credential type (selected via credential_type) into an API key.
func TestAWSDriver_SecretsManager_APIKey_RoundTrip(t *testing.T) {
	var gotToken string
	stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.Form.Get("WebIdentityToken")
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretexample</SecretAccessKey>
      <SessionToken>tokenexample</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	defer stsSrv.Close()

	// The stored secret holds an API key, not AWS access keys — the mint path does not
	// care about the shape; the credential type does.
	smSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Name":"prod/app/openai","SecretString":"{\"api_key\":\"sk-test-123\"}"}`))
	}))
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"})},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(stsSrv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
		smBaseEndpoint: smSrv.URL,
	}
	spec := &credential.CredSpec{Name: "openai", Config: credential.NewConfig(map[string]string{
		"mint_method":     "secrets_manager",
		"credential_type": "api_key",
		"secret_id":       "prod/app/openai",
		"role_arn":        "arn:aws:iam::123456789012:role/WardenSecretsReader",
	})}
	inputs := &credential.ExchangeInputs{
		SubjectToken:     "eyJ.warden.assertion",
		SubjectTokenType: credential.TokenTypeJWT,
	}

	// Mint: the driver fetches the raw secret, shape-agnostic.
	rawData, _, _, _, err := drv.MintCredentialWithExchange(context.TODO(), spec, inputs)
	require.NoError(t, err)
	assert.Equal(t, "eyJ.warden.assertion", gotToken)

	// The spec selected api_key, so the api_key type parses the fetched blob into a
	// well-formed API key credential (reusing its validation and masking).
	inferred, err := (&AWSDriverFactory{}).InferCredentialType(spec.Config)
	require.NoError(t, err)
	require.Equal(t, credential.TypeAPIKey, inferred)

	apiKeyType := types.NewAPIKeyCredType()
	cred, err := apiKeyType.Parse(rawData, nil, 0, "")
	require.NoError(t, err)
	require.NoError(t, apiKeyType.Validate(cred))
	assert.Equal(t, credential.TypeAPIKey, cred.Type)
	assert.Equal(t, "sk-test-123", cred.Data["api_key"])
}

// =============================================================================
// AzureDriver readLimitedBody Test
// =============================================================================

func TestAWSAssertionAudience(t *testing.T) {
	t.Run("federation default", func(t *testing.T) {
		aud, ok := awsAssertionAudience(credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}))
		require.True(t, ok)
		assert.Equal(t, "sts.amazonaws.com", aud)
	})

	t.Run("federation explicit override", func(t *testing.T) {
		aud, ok := awsAssertionAudience(credential.NewConfig(map[string]string{"auth_method": "oidc_federation", "audience": "my-client-id"}))
		require.True(t, ok)
		assert.Equal(t, "my-client-id", aud)
	})

	t.Run("static source derives nothing", func(t *testing.T) {
		_, ok := awsAssertionAudience(credential.NewConfig(map[string]string{"auth_method": "static"}))
		assert.False(t, ok)
	})

	t.Run("routed via DeriveAssertionAudience", func(t *testing.T) {
		aud, ok := DeriveAssertionAudience(credential.SourceTypeAWS, credential.NewConfig(map[string]string{"auth_method": "oidc_federation"}), credential.NewConfig(map[string]string{}))
		require.True(t, ok)
		assert.Equal(t, "sts.amazonaws.com", aud)
	})
}

func TestAWSValidateConfig_AudienceOnlyFederation(t *testing.T) {
	f := &AWSDriverFactory{}

	t.Run("audience rejected on static", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method":       "static",
			"access_key_id":     "AKIA",
			"secret_access_key": "sk",
			"region":            "us-east-1",
			"audience":          "sts.amazonaws.com",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only valid for auth_method=oidc_federation")
	})

	t.Run("audience allowed on federation", func(t *testing.T) {
		err := f.ValidateConfig(credential.NewConfig(map[string]string{
			"auth_method": "oidc_federation",
			"region":      "us-east-1",
			"audience":    "my-client-id",
		}))
		require.NoError(t, err)
	})
}

// =============================================================================
// Endpoint overrides (sts_endpoint / secretsmanager_endpoint)
// =============================================================================

// stsStub answers the three STS actions the driver calls, recording each one. The
// AssumeRole and AssumeRoleWithWebIdentity results share a credential shape, so one
// handler covers every path that needs an STS endpoint.
func stsStub(t *testing.T, actions *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		*actions = append(*actions, action)
		w.Header().Set("Content-Type", "text/xml")

		creds := `<Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretexample</SecretAccessKey>
      <SessionToken>tokenexample</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/App/warden</Arn>
      <AssumedRoleId>AROAEXAMPLE:warden</AssumedRoleId>
    </AssumedRoleUser>`

		switch action {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/warden</Arn>
    <UserId>AIDAEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>`))
		case "AssumeRole":
			_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    ` + creds + `
  </AssumeRoleResult>
</AssumeRoleResponse>`))
		case "AssumeRoleWithWebIdentity":
			_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    ` + creds + `
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

// smStub answers GetSecretValue with the given JSON payload, recording the target
// and the SigV4 scope of each call.
func smStub(t *testing.T, payload string, target, authScope *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*target = r.Header.Get("X-Amz-Target")
		*authScope = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		body, _ := json.Marshal(map[string]string{"Name": "prod/app", "SecretString": payload})
		_, _ = w.Write(body)
	}))
}

// TestAWSDriver_EndpointOverride_StaticSourceValidation pins the case a partial
// application of the override would break: creating a static source runs a
// GetCallerIdentity probe, which must reach the configured endpoint rather than the
// real service. Without sts_endpoint on the authenticateLocked client, Create here
// would call AWS and fail.
func TestAWSDriver_EndpointOverride_StaticSourceValidation(t *testing.T) {
	var actions []string
	srv := stsStub(t, &actions)
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region":            "us-east-1",
		"sts_endpoint":      srv.URL,
	}), log)
	require.NoError(t, err)
	assert.Equal(t, []string{"GetCallerIdentity"}, actions)
	assert.Equal(t, srv.URL, drv.(*AWSDriver).stsEndpoint)
}

// TestAWSDriver_EndpointOverride_AssumeRoleSource covers the second STS client on the
// source-creation path: a source with assume_role_arn calls AssumeRole instead of the
// base-credential probe.
func TestAWSDriver_EndpointOverride_AssumeRoleSource(t *testing.T) {
	var actions []string
	srv := stsStub(t, &actions)
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	_, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region":            "us-east-1",
		"assume_role_arn":   "arn:aws:iam::123456789012:role/WardenSourceRole",
		"sts_endpoint":      srv.URL,
	}), log)
	require.NoError(t, err)
	assert.Equal(t, []string{"AssumeRole"}, actions)
}

// TestAWSDriver_EndpointOverride_SecretsManagerMint proves the override reaches the
// Secrets Manager client in the driver's client generation, i.e. the static mint path.
func TestAWSDriver_EndpointOverride_SecretsManagerMint(t *testing.T) {
	var actions []string
	stsSrv := stsStub(t, &actions)
	defer stsSrv.Close()

	var target, authScope string
	smSrv := smStub(t, `{"api_key":"stored-key"}`, &target, &authScope)
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":           "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key":       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.URL,
		"secretsmanager_endpoint": smSrv.URL,
	}), log)
	require.NoError(t, err)

	rawData, _, _, _, err := drv.MintCredential(context.TODO(), &credential.CredSpec{
		Name:   "sm",
		Config: credential.NewConfig(map[string]string{"mint_method": "secrets_manager", "secret_id": "prod/app"}),
	})
	require.NoError(t, err)
	assert.Contains(t, target, "GetSecretValue")
	assert.Contains(t, authScope, "AKIAIOSFODNN7EXAMPLE", "the static mint must sign with the source's own key")
	assert.Equal(t, "stored-key", rawData["api_key"])
}

// TestAWSDriver_EndpointOverride_WebIdentity proves both overrides reach a keyless
// source built through the factory: the anonymous STS client and the client bound to
// the freshly federated credentials.
func TestAWSDriver_EndpointOverride_WebIdentity(t *testing.T) {
	var actions []string
	stsSrv := stsStub(t, &actions)
	defer stsSrv.Close()

	var target, authScope string
	smSrv := smStub(t, `{"api_key":"federated-key"}`, &target, &authScope)
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"auth_method":             "oidc_federation",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.URL,
		"secretsmanager_endpoint": smSrv.URL,
	}), log)
	require.NoError(t, err)

	spec := &credential.CredSpec{Name: "sm", Config: credential.NewConfig(map[string]string{
		"mint_method": "secrets_manager",
		"secret_id":   "prod/app",
		"role_arn":    "arn:aws:iam::123456789012:role/App",
	})}
	rawData, _, _, _, err := drv.(*AWSDriver).MintCredentialWithExchange(context.TODO(), spec, &credential.ExchangeInputs{
		SubjectToken:     "eyJ.warden.assertion",
		SubjectTokenType: credential.TokenTypeJWT,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"AssumeRoleWithWebIdentity"}, actions)
	assert.Contains(t, target, "GetSecretValue")
	assert.Contains(t, authScope, "ASIAEXAMPLE", "the fetch must be signed with the federated credentials")
	assert.Equal(t, "federated-key", rawData["api_key"])
}

// TestAWSDriver_EndpointOverride_AbsentLeavesResolverAlone: a source that sets neither
// key must leave both empty, so the SDK resolves the real regional endpoints.
func TestAWSDriver_EndpointOverride_AbsentLeavesResolverAlone(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"auth_method": "oidc_federation",
		"region":      "us-east-1",
	}), log)
	require.NoError(t, err)
	awsDrv := drv.(*AWSDriver)
	assert.Empty(t, awsDrv.stsEndpoint)
	assert.Empty(t, awsDrv.smBaseEndpoint)

	// The option funcs are what actually decide the endpoint, so assert on them
	// rather than on the fields they read: with nothing configured they must leave
	// BaseEndpoint untouched, so the SDK resolves the real regional endpoint.
	stsOpts := sts.Options{}
	awsDrv.stsOptions()(&stsOpts)
	assert.Nil(t, stsOpts.BaseEndpoint)

	smOpts := secretsmanager.Options{}
	awsDrv.smOptions()(&smOpts)
	assert.Nil(t, smOpts.BaseEndpoint)
}

// =============================================================================
// Client generations: concurrency, timeouts, transport
// =============================================================================

// concurrentSTSStub is stsStub's thread-safe sibling. The concurrency tests drive
// it from many goroutines at once, so it records under a mutex and reports the
// SigV4 scope of every request it saw.
type concurrentSTSStub struct {
	mu       sync.Mutex
	requests []stsRequest
	srv      *httptest.Server
}

// stsRequest is one call the stub saw: the action and the SigV4 scope it was
// signed with, which is how a test tells one key generation from another.
type stsRequest struct {
	action string
	scope  string
}

func newConcurrentSTSStub(t *testing.T) *concurrentSTSStub {
	t.Helper()
	s := &concurrentSTSStub{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.Form.Get("Action")

		s.mu.Lock()
		s.requests = append(s.requests, stsRequest{action: action, scope: r.Header.Get("Authorization")})
		s.mu.Unlock()

		const credsXML = `<Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretexample</SecretAccessKey>
      <SessionToken>tokenexample</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/App/w</Arn><AssumedRoleId>AROA:w</AssumedRoleId></AssumedRoleUser>`

		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/w</Arn><UserId>AIDA</UserId><Account>123456789012</Account></GetCallerIdentityResult>
</GetCallerIdentityResponse>`))
		case "AssumeRoleWithWebIdentity":
			_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>` + credsXML + `</AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
		default:
			_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>` + credsXML + `</AssumeRoleResult>
</AssumeRoleResponse>`))
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// TestAWSDriver_ConcurrentMintAndRotationCommit drives mints and rotation commits
// against one driver instance, which is how the registry hands drivers out. The
// assertion that matters is -race staying quiet: before the client generations
// were snapshotted, every commit rebuilt fields that in-flight mints were reading
// without the lock.
func TestAWSDriver_ConcurrentMintAndRotationCommit(t *testing.T) {
	stub := newConcurrentSTSStub(t)

	var target, authScope string
	var smMu sync.Mutex
	smSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		smMu.Lock()
		target, authScope = r.Header.Get("X-Amz-Target"), r.Header.Get("Authorization")
		smMu.Unlock()
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Name":"prod/app","SecretString":"{\"api_key\":\"k\"}"}`))
	}))
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	baseConfig := map[string]string{
		"access_key_id":           "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key":       "secret0",
		"region":                  "us-east-1",
		"sts_endpoint":            stub.srv.URL,
		"secretsmanager_endpoint": smSrv.URL,
	}
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(baseConfig), log)
	require.NoError(t, err)
	awsDrv := drv.(*AWSDriver)

	roleSpec := &credential.CredSpec{Name: "role", Config: credential.NewConfig(map[string]string{
		"mint_method": "sts_assume_role", "role_arn": "arn:aws:iam::123456789012:role/App", "ttl": "1h",
	})}
	smSpec := &credential.CredSpec{Name: "sm", Config: credential.NewConfig(map[string]string{
		"mint_method": "secrets_manager", "secret_id": "prod/app",
	})}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			spec := roleSpec
			if i%2 == 0 {
				spec = smSpec
			}
			for n := 0; n < 15; n++ {
				if _, _, _, _, err := drv.MintCredential(context.TODO(), spec); err != nil {
					t.Errorf("mint failed: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 15; n++ {
			rotated := make(map[string]string, len(baseConfig))
			for k, v := range baseConfig {
				rotated[k] = v
			}
			rotated["secret_access_key"] = fmt.Sprintf("secret%d", n+1)
			if err := awsDrv.CommitRotation(context.TODO(), rotated); err != nil {
				t.Errorf("commit failed: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	smMu.Lock()
	defer smMu.Unlock()
	assert.Contains(t, target, "GetSecretValue")
	assert.NotEmpty(t, authScope)
}

// TestAWSDriver_MintSignsWithOneGeneration pins the property the snapshot exists
// for: a commit landing in the middle of a mint must not change which credentials
// that mint's request is signed with. The stub gives the rotation a deterministic
// seam rather than racing it with a sleep.
func TestAWSDriver_SnapshotSurvivesRotationCommit(t *testing.T) {
	stub := newConcurrentSTSStub(t)

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	baseConfig := map[string]string{
		"access_key_id":     "AKIAOLDEXAMPLEKEY000",
		"secret_access_key": "old-secret",
		"region":            "us-east-1",
		"sts_endpoint":      stub.srv.URL,
	}
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(baseConfig), log)
	require.NoError(t, err)
	awsDrv := drv.(*AWSDriver)

	rotated := make(map[string]string, len(baseConfig))
	for k, v := range baseConfig {
		rotated[k] = v
	}
	rotated["access_key_id"] = "AKIANEWEXAMPLEKEY000"
	rotated["secret_access_key"] = "new-secret"

	// Take a generation the way a mint does, then rotate underneath it.
	held, err := awsDrv.authenticate(context.TODO())
	require.NoError(t, err)
	require.NoError(t, awsDrv.CommitRotation(context.TODO(), rotated))

	// The held generation still signs with the key it was built from. This is the
	// property the snapshot exists for: a mint that authenticated before a commit
	// finishes its calls on one set of credentials rather than a mixture.
	_, err = held.sts.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::123456789012:role/App"),
		RoleSessionName: aws.String("held"),
	})
	require.NoError(t, err)
	assert.Contains(t, lastAssumeRoleScope(t, stub), "AKIAOLDEXAMPLEKEY000",
		"a generation taken before the commit must keep signing with its own key")

	// A fresh generation picks up the rotated key, and is not the held one.
	fresh, err := awsDrv.authenticate(context.TODO())
	require.NoError(t, err)
	assert.NotSame(t, held, fresh, "the commit must drop the stale generation")

	_, err = fresh.sts.AssumeRole(context.TODO(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::123456789012:role/App"),
		RoleSessionName: aws.String("fresh"),
	})
	require.NoError(t, err)
	assert.Contains(t, lastAssumeRoleScope(t, stub), "AKIANEWEXAMPLEKEY000")
}

// lastAssumeRoleScope returns the SigV4 scope of the most recent AssumeRole the
// stub saw. Filtering by action matters: the Create-time probe signs a
// GetCallerIdentity with the pre-rotation key, so scanning every request would
// find the old key whatever the code under test did.
func lastAssumeRoleScope(t *testing.T, s *concurrentSTSStub) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.requests) - 1; i >= 0; i-- {
		if s.requests[i].action == "AssumeRole" {
			return s.requests[i].scope
		}
	}
	t.Fatal("stub saw no AssumeRole request")
	return ""
}

// TestAWSDriver_Create_ProbeTimesOut: an endpoint that accepts the connection and
// never answers must fail the source write, not hold it open.
func TestAWSDriver_Create_ProbeTimesOut(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// Release the handler before closing: Close waits for it to return.
	defer srv.Close()
	defer close(block)

	orig := awsCreateProbeTimeout
	awsCreateProbeTimeout = 200 * time.Millisecond
	defer func() { awsCreateProbeTimeout = orig }()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	start := time.Now()
	_, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "secret",
		"region":            "us-east-1",
		"sts_endpoint":      srv.URL,
	}), log)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 10*time.Second, "Create must give up on the probe timeout")
}

// TestAWSDriver_HTTPClientReachesClients proves the configured transport is the one
// the SDK uses: the stub speaks TLS with an untrusted certificate, so the probe can
// only succeed if the driver's own client (built with tls_skip_verify) is in play.
func TestAWSDriver_HTTPClientReachesClients(t *testing.T) {
	var actions []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		actions = append(actions, r.Form.Get("Action"))
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/w</Arn><UserId>AIDA</UserId><Account>123456789012</Account></GetCallerIdentityResult>
</GetCallerIdentityResponse>`))
	}))
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	cfg := map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "secret",
		"region":            "us-east-1",
		"sts_endpoint":      srv.URL,
	}

	_, err := (&AWSDriverFactory{}).Create(credential.NewConfig(cfg), log)
	require.Error(t, err, "without tls_skip_verify the untrusted certificate must be rejected")

	cfg["tls_skip_verify"] = "true"
	_, err = (&AWSDriverFactory{}).Create(credential.NewConfig(cfg), log)
	require.NoError(t, err)
	assert.Equal(t, []string{"GetCallerIdentity"}, actions)
}

// TestAWSDriver_MintViaRDSIAMToken_HappyPath covers the RDS path under the snapshot
// signature. The token is signed locally, so no endpoint is involved.
func TestAWSDriver_MintViaRDSIAMToken_HappyPath(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{
			"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "secret", "region": "us-east-1",
		})},
		baseCreds: credentials.NewStaticCredentialsProvider("AKIAIOSFODNN7EXAMPLE", "secret", ""),
		region:    "us-east-1",
	}
	primeClients(driver)

	rawData, metadata, ttl, leaseID, err := driver.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "db",
		Config: credential.NewConfig(map[string]string{
			"mint_method": "rds_iam_token",
			"db_endpoint": "mydb.abc123.us-east-1.rds.amazonaws.com",
			"db_user":     "app",
		}),
	})
	require.NoError(t, err)
	assert.Contains(t, rawData["auth_token"], "X-Amz-Signature=")
	assert.Equal(t, "5432", rawData["db_port"])
	assert.Equal(t, "rds_iam", rawData["token_type"])
	assert.Nil(t, metadata)
	assert.Equal(t, 15*time.Minute, ttl)
	assert.Equal(t, "", leaseID)
}

// iamKey is one entry the IAM stub reports from ListAccessKeys.
type iamKey struct {
	id     string
	status string // "Active" or "Inactive"
}

// iamCall is one request the stub saw: the action and the key it named, which is
// how a test checks that rotation touched the key it meant to and no other.
type iamCall struct {
	action string
	keyID  string
	status string // the Status parameter, for UpdateAccessKey
}

// iamStubOpts configures the stub for one test.
type iamStubOpts struct {
	keys []iamKey
	// onCreateKey, when set, runs while the CreateAccessKey call is in flight —
	// the seam a rotation commit needs to land inside a prepare, after it has
	// snapshotted the config and before it builds its result from it.
	onCreateKey func()
	// noSuchEntity makes every mutating call report the key as already gone.
	noSuchEntity bool
}

// iamStub answers the IAM calls rotation makes, recording each one. IAM speaks the
// same query/XML protocol as STS.
func iamStub(t *testing.T, calls *[]iamCall, mu *sync.Mutex, opts iamStubOpts) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		mu.Lock()
		*calls = append(*calls, iamCall{
			action: action,
			keyID:  r.Form.Get("AccessKeyId"),
			status: r.Form.Get("Status"),
		})
		mu.Unlock()

		if action == "CreateAccessKey" && opts.onCreateKey != nil {
			opts.onCreateKey()
		}

		w.Header().Set("Content-Type", "text/xml")

		if opts.noSuchEntity && (action == "DeleteAccessKey" || action == "UpdateAccessKey") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>key not found</Message></Error>
</ErrorResponse>`))
			return
		}

		switch action {
		case "ListAccessKeys":
			members := ""
			for _, k := range opts.keys {
				members += `<member><UserName>w</UserName><AccessKeyId>` + k.id +
					`</AccessKeyId><Status>` + k.status + `</Status></member>`
			}
			_, _ = w.Write([]byte(`<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListAccessKeysResult><IsTruncated>false</IsTruncated><AccessKeyMetadata>` + members +
				`</AccessKeyMetadata></ListAccessKeysResult>
</ListAccessKeysResponse>`))
		case "CreateAccessKey":
			_, _ = w.Write([]byte(`<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <CreateAccessKeyResult><AccessKey>
    <UserName>w</UserName><AccessKeyId>AKIAMINTEDEXAMPLE000</AccessKeyId>
    <SecretAccessKey>minted-secret</SecretAccessKey><Status>Active</Status>
  </AccessKey></CreateAccessKeyResult>
</CreateAccessKeyResponse>`))
		default:
			_, _ = w.Write([]byte(`<Response xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></Response>`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAWSDriver_PrepareRotation_UsesOneConfigGeneration pins that prepare builds
// its result from the config it snapshotted, not from whatever is live when it
// finishes. Reading the live field would let a commit landing mid-prepare produce
// a new config derived from one generation while cleanup names another's key.
func TestAWSDriver_PrepareRotation_UsesOneConfigGeneration(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	baseConfig := map[string]string{
		"access_key_id":     "AKIAOLDEXAMPLEKEY000",
		"secret_access_key": "old-secret",
		"region":            "us-east-1",
		"sts_endpoint":      stsSrv.srv.URL,
		"activation_delay":  "7m",
	}

	var awsDrv *AWSDriver
	var iamCalls []iamCall
	var iamMu sync.Mutex

	// The interloping commit fires while prepare's CreateAccessKey is in flight:
	// after prepare snapshotted the config, before it builds its result from it.
	iamSrv := iamStub(t, &iamCalls, &iamMu, iamStubOpts{
		keys: []iamKey{{id: "AKIAOLDEXAMPLEKEY000", status: "Active"}},
		onCreateKey: func() {
			if err := awsDrv.CommitRotation(context.TODO(), map[string]string{
				"access_key_id":     "AKIAINTERLOPERKEY000",
				"secret_access_key": "interloper-secret",
				"region":            "us-east-1",
				"sts_endpoint":      stsSrv.srv.URL,
				"activation_delay":  "99m",
			}); err != nil {
				t.Errorf("interloping commit failed: %v", err)
			}
		},
	})

	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(baseConfig), log)
	require.NoError(t, err)
	awsDrv = drv.(*AWSDriver)
	awsDrv.iamTestEndpoint = iamSrv.URL

	newConfig, cleanupConfig, activateAfter, err := awsDrv.PrepareRotation(context.TODO())
	require.NoError(t, err)

	// Everything prepare returns must come from one generation: the key it minted,
	// plus the config it snapshotted — never the one the commit installed midway.
	assert.Equal(t, "AKIAMINTEDEXAMPLE000", newConfig["access_key_id"])
	assert.Equal(t, "minted-secret", newConfig["secret_access_key"])
	assert.Equal(t, "AKIAOLDEXAMPLEKEY000", cleanupConfig["access_key_id"],
		"cleanup must name the key that was current when prepare snapshotted")
	assert.Equal(t, "7m", newConfig["activation_delay"],
		"the carried-over config must come from the same snapshot as the old key id")
	assert.Equal(t, 7*time.Minute, activateAfter)
}

// TestAWSDriver_FederatedSecretsManagerUsesConfiguredTransport: the keyless fetch
// builds its Secrets Manager client per request, so it has to pick up the source's
// transport too — otherwise the STS leg honours a custom CA and the fetch does not.
func TestAWSDriver_FederatedSecretsManagerUsesConfiguredTransport(t *testing.T) {
	var stsActions []string
	stsSrv := stsStub(t, &stsActions)
	defer stsSrv.Close()

	var target, authScope string
	smSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, authScope = r.Header.Get("X-Amz-Target"), r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Name":"prod/app","SecretString":"{\"api_key\":\"federated\"}"}`))
	}))
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"auth_method":             "oidc_federation",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.URL,
		"secretsmanager_endpoint": smSrv.URL,
		"tls_skip_verify":         "true",
	}), log)
	require.NoError(t, err)

	spec := &credential.CredSpec{Name: "sm", Config: credential.NewConfig(map[string]string{
		"mint_method": "secrets_manager",
		"secret_id":   "prod/app",
		"role_arn":    "arn:aws:iam::123456789012:role/App",
	})}
	rawData, _, _, _, err := drv.(*AWSDriver).MintCredentialWithExchange(context.TODO(), spec, &credential.ExchangeInputs{
		SubjectToken:     "eyJ.warden.assertion",
		SubjectTokenType: credential.TokenTypeJWT,
	})
	require.NoError(t, err)
	assert.Contains(t, target, "GetSecretValue")
	assert.Contains(t, authScope, "ASIAEXAMPLE")
	assert.Equal(t, "federated", rawData["api_key"])
}

// =============================================================================
// Malformed responses
// =============================================================================

func TestValidSTSCredentials(t *testing.T) {
	full := func() *ststypes.Credentials {
		return &ststypes.Credentials{
			AccessKeyId:     aws.String("ASIA"),
			SecretAccessKey: aws.String("s"),
			SessionToken:    aws.String("t"),
			Expiration:      aws.Time(time.Now().Add(time.Hour)),
		}
	}

	tests := []struct {
		name   string
		creds  func() *ststypes.Credentials
		errMsg string
	}{
		{name: "complete", creds: full},
		{
			name:   "no block",
			creds:  func() *ststypes.Credentials { return nil },
			errMsg: "returned no credentials block",
		},
		{
			name:   "no access key id",
			creds:  func() *ststypes.Credentials { c := full(); c.AccessKeyId = nil; return c },
			errMsg: "no AccessKeyId",
		},
		{
			name:   "no secret access key",
			creds:  func() *ststypes.Credentials { c := full(); c.SecretAccessKey = nil; return c },
			errMsg: "no SecretAccessKey",
		},
		{
			name:   "no session token",
			creds:  func() *ststypes.Credentials { c := full(); c.SessionToken = nil; return c },
			errMsg: "no SessionToken",
		},
		{
			name:   "no expiration",
			creds:  func() *ststypes.Credentials { c := full(); c.Expiration = nil; return c },
			errMsg: "no Expiration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validSTSCredentials(tt.creds(), "STS AssumeRole for arn:x")
			if tt.errMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
			assert.Contains(t, err.Error(), "arn:x", "the error must name the call it came from")
		})
	}
}

// malformedSTSStub answers the assume-role calls with the given credentials XML
// fragment, so a test can omit the block entirely or leave one field out of it.
// GetCallerIdentity always succeeds, so Create gets far enough to reach the call
// under test.
func malformedSTSStub(t *testing.T, credsXML string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/xml")
		switch r.Form.Get("Action") {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/w</Arn><UserId>AIDA</UserId><Account>123456789012</Account></GetCallerIdentityResult>
</GetCallerIdentityResponse>`))
		case "AssumeRoleWithWebIdentity":
			_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>` + credsXML + `</AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
		default:
			_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>` + credsXML + `</AssumeRoleResult>
</AssumeRoleResponse>`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const (
	// noCredentialsBlock is a 200 whose result carries no <Credentials> at all —
	// the SDK leaves the struct nil.
	noCredentialsBlock = `<AssumedRoleUser><Arn>arn:aws:sts::1:assumed-role/App/w</Arn><AssumedRoleId>AROA:w</AssumedRoleId></AssumedRoleUser>`

	// partialCredentialsBlock has the struct but omits one field, which the SDK
	// leaves as a nil pointer inside a non-nil struct.
	partialCredentialsBlock = `<Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SessionToken>tokenexample</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>`
)

// TestAWSDriver_MintViaSTSAssumeRole_MalformedResponse: a half-formed 200 must
// surface as an error naming the missing field, not a panic in the broker.
func TestAWSDriver_MintViaSTSAssumeRole_MalformedResponse(t *testing.T) {
	for _, tt := range []struct {
		name   string
		xml    string
		errMsg string
	}{
		{"no credentials block", noCredentialsBlock, "returned no credentials block"},
		{"missing secret access key", partialCredentialsBlock, "no SecretAccessKey"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := malformedSTSStub(t, tt.xml)

			log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
			drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
				"sts_endpoint":      srv.URL,
			}), log)
			require.NoError(t, err)

			_, _, _, _, err = drv.MintCredential(context.TODO(), &credential.CredSpec{
				Name: "role",
				Config: credential.NewConfig(map[string]string{
					"mint_method": "sts_assume_role",
					"role_arn":    "arn:aws:iam::123456789012:role/App",
					"ttl":         "1h",
				}),
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestAWSDriver_WebIdentity_MalformedResponse covers the same on the keyless path.
// The guard there also protects the credential provider the federated secret fetch
// is built from, whose fields are read through aws.ToString and would otherwise
// become empty strings rather than panicking — a request signed with nothing.
func TestAWSDriver_WebIdentity_MalformedResponse(t *testing.T) {
	for _, tt := range []struct {
		name   string
		xml    string
		errMsg string
	}{
		{"no credentials block", noCredentialsBlock, "returned no credentials block"},
		{"missing secret access key", partialCredentialsBlock, "no SecretAccessKey"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := malformedSTSStub(t, tt.xml)

			log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
			drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
				"auth_method":  "oidc_federation",
				"region":       "us-east-1",
				"sts_endpoint": srv.URL,
			}), log)
			require.NoError(t, err)

			spec := &credential.CredSpec{Name: "wid", Config: credential.NewConfig(map[string]string{
				"mint_method": "sts_assume_role",
				"role_arn":    "arn:aws:iam::123456789012:role/App",
				"ttl":         "15m",
			})}
			_, _, _, _, err = drv.(*AWSDriver).MintCredentialWithExchange(context.TODO(), spec,
				&credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenType: credential.TokenTypeJWT})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestAWSDriver_Create_AssumeRoleSource_MalformedResponse: the same guard on the
// source-creation path, where a nil dereference would take down a write rather
// than a mint.
func TestAWSDriver_Create_AssumeRoleSource_MalformedResponse(t *testing.T) {
	srv := malformedSTSStub(t, noCredentialsBlock)

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	_, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "secret",
		"region":            "us-east-1",
		"assume_role_arn":   "arn:aws:iam::123456789012:role/WardenSourceRole",
		"sts_endpoint":      srv.URL,
	}), log)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned no credentials block")
}

func TestValidNewIAMAccessKey(t *testing.T) {
	require.NoError(t, validNewIAMAccessKey(&iamtypes.AccessKey{
		AccessKeyId: aws.String("AKIA"), SecretAccessKey: aws.String("s"),
	}))

	err := validNewIAMAccessKey(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no access key")

	err = validNewIAMAccessKey(&iamtypes.AccessKey{SecretAccessKey: aws.String("s")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no AccessKeyId")

	err = validNewIAMAccessKey(&iamtypes.AccessKey{AccessKeyId: aws.String("AKIA")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SecretAccessKey")
}

// TestAWSDriver_PrepareRotation_MalformedCreateKeyResponse: rotation must refuse a
// key it cannot fully read rather than persist a half-empty credential as the
// source's only key.
func TestAWSDriver_PrepareRotation_MalformedCreateKeyResponse(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)

	iamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/xml")
		if r.Form.Get("Action") == "ListAccessKeys" {
			_, _ = w.Write([]byte(`<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListAccessKeysResult><IsTruncated>false</IsTruncated><AccessKeyMetadata>
    <member><UserName>w</UserName><AccessKeyId>AKIAOLDEXAMPLEKEY000</AccessKeyId><Status>Active</Status></member>
  </AccessKeyMetadata></ListAccessKeysResult>
</ListAccessKeysResponse>`))
			return
		}
		// A CreateAccessKey whose key carries no secret.
		_, _ = w.Write([]byte(`<CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <CreateAccessKeyResult><AccessKey>
    <UserName>w</UserName><AccessKeyId>AKIAMINTEDEXAMPLE000</AccessKeyId><Status>Active</Status>
  </AccessKey></CreateAccessKeyResult>
</CreateAccessKeyResponse>`))
	}))
	defer iamSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAOLDEXAMPLEKEY000",
		"secret_access_key": "old-secret",
		"region":            "us-east-1",
		"sts_endpoint":      stsSrv.srv.URL,
	}), log)
	require.NoError(t, err)
	awsDrv := drv.(*AWSDriver)
	awsDrv.iamTestEndpoint = iamSrv.URL

	_, _, _, err = awsDrv.PrepareRotation(context.TODO())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SecretAccessKey")
}

// =============================================================================
// Rotation safety
// =============================================================================

// rotationDriver builds a driver wired to an STS stub and the given IAM stub,
// configured with a rotatable (AKIA-prefixed) key.
func rotationDriver(t *testing.T, stsURL, iamURL, accessKeyID string) *AWSDriver {
	t.Helper()
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     accessKeyID,
		"secret_access_key": "old-secret",
		"region":            "us-east-1",
		"sts_endpoint":      stsURL,
	}), log)
	require.NoError(t, err)
	awsDrv := drv.(*AWSDriver)
	awsDrv.iamTestEndpoint = iamURL
	return awsDrv
}

func iamActionsOf(calls []iamCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.action)
	}
	return out
}

// TestAWSDriver_PrepareRotation_RefusesUnownedKeyList: if the configured key is not
// among the ones listed, the source's credentials belong to a different IAM user
// than the one being listed. Every key there is someone else's, so touch none.
func TestAWSDriver_PrepareRotation_RefusesUnownedKeyList(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)
	var calls []iamCall
	var mu sync.Mutex
	iamSrv := iamStub(t, &calls, &mu, iamStubOpts{keys: []iamKey{
		{id: "AKIASTRANGERONE00000", status: "Active"},
		{id: "AKIASTRANGERTWO00000", status: "Active"},
	}})

	awsDrv := rotationDriver(t, stsSrv.srv.URL, iamSrv.URL, "AKIAOLDEXAMPLEKEY000")

	_, _, _, err := awsDrv.PrepareRotation(context.TODO())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to remove a key this source does not own")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"ListAccessKeys"}, iamActionsOf(calls),
		"a list it does not recognise must be read and nothing else")
}

// TestAWSDriver_PrepareRotation_DeactivatesActiveStranger: an active non-current
// key is disabled rather than destroyed, and the attempt stops so the retry can
// reclaim the slot once the key is safely inactive.
func TestAWSDriver_PrepareRotation_DeactivatesActiveStranger(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)
	var calls []iamCall
	var mu sync.Mutex
	iamSrv := iamStub(t, &calls, &mu, iamStubOpts{keys: []iamKey{
		{id: "AKIAOLDEXAMPLEKEY000", status: "Active"},
		{id: "AKIASTRANGERONE00000", status: "Active"},
	}})

	awsDrv := rotationDriver(t, stsSrv.srv.URL, iamSrv.URL, "AKIAOLDEXAMPLEKEY000")

	_, _, _, err := awsDrv.PrepareRotation(context.TODO())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deactivated and will be removed on the next rotation attempt")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"ListAccessKeys", "UpdateAccessKey"}, iamActionsOf(calls),
		"nothing may be deleted, and no key minted, on this attempt")
	assert.Equal(t, "AKIASTRANGERONE00000", calls[1].keyID)
	assert.Equal(t, "Inactive", calls[1].status)
}

// TestAWSDriver_PrepareRotation_ReclaimsInactiveOrphan: an inactive non-current key
// is what an interrupted cleanup leaves behind, so it is attributable and can be
// deleted to free the slot.
func TestAWSDriver_PrepareRotation_ReclaimsInactiveOrphan(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)
	var calls []iamCall
	var mu sync.Mutex
	iamSrv := iamStub(t, &calls, &mu, iamStubOpts{keys: []iamKey{
		{id: "AKIAOLDEXAMPLEKEY000", status: "Active"},
		{id: "AKIAORPHANKEY0000000", status: "Inactive"},
	}})

	awsDrv := rotationDriver(t, stsSrv.srv.URL, iamSrv.URL, "AKIAOLDEXAMPLEKEY000")

	newConfig, cleanupConfig, _, err := awsDrv.PrepareRotation(context.TODO())
	require.NoError(t, err)
	assert.Equal(t, "AKIAMINTEDEXAMPLE000", newConfig["access_key_id"])
	assert.Equal(t, "AKIAOLDEXAMPLEKEY000", cleanupConfig["access_key_id"])

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"ListAccessKeys", "DeleteAccessKey", "CreateAccessKey"}, iamActionsOf(calls))
	assert.Equal(t, "AKIAORPHANKEY0000000", calls[1].keyID, "only the orphan may be deleted")
}

// TestAWSDriver_CommitRotation_VerifyFailureKeepsInstanceOnOldKey: a commit whose
// verification fails must leave this driver instance whole, so in-flight and
// subsequent mints on it keep working with the credentials it already had.
//
// This is deliberately a claim about the instance, not about what the next request
// sees: the manager persists the new config and closes the driver before calling
// commit, so a later request is served by a fresh instance built from the persisted
// key regardless.
func TestAWSDriver_CommitRotation_VerifyFailureKeepsInstanceOnOldKey(t *testing.T) {
	var mu sync.Mutex
	var requests []stsRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action, auth := r.Form.Get("Action"), r.Header.Get("Authorization")
		mu.Lock()
		requests = append(requests, stsRequest{action: action, scope: auth})
		mu.Unlock()

		w.Header().Set("Content-Type", "text/xml")
		// The new key is rejected; the old one still works.
		if strings.Contains(auth, "AKIANEWEXAMPLEKEY000") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>InvalidClientTokenId</Code><Message>invalid key</Message></Error>
</ErrorResponse>`))
			return
		}
		switch action {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/w</Arn><UserId>AIDA</UserId><Account>123456789012</Account></GetCallerIdentityResult>
</GetCallerIdentityResponse>`))
		default:
			_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult><Credentials>
    <AccessKeyId>ASIAEXAMPLE</AccessKeyId><SecretAccessKey>s</SecretAccessKey>
    <SessionToken>t</SessionToken><Expiration>2035-01-01T00:00:00Z</Expiration>
  </Credentials><AssumedRoleUser><Arn>arn:aws:sts::1:assumed-role/App/w</Arn><AssumedRoleId>AROA:w</AssumedRoleId></AssumedRoleUser></AssumeRoleResult>
</AssumeRoleResponse>`))
		}
	}))
	defer srv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAOLDEXAMPLEKEY000",
		"secret_access_key": "old-secret",
		"region":            "us-east-1",
		"sts_endpoint":      srv.URL,
	}), log)
	require.NoError(t, err)
	awsDrv := drv.(*AWSDriver)

	err = awsDrv.CommitRotation(context.TODO(), map[string]string{
		"access_key_id":     "AKIANEWEXAMPLEKEY000",
		"secret_access_key": "new-secret",
		"region":            "us-east-1",
		"sts_endpoint":      srv.URL,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to authenticate with new IAM keys")

	// The instance still mints, still on the old key.
	_, _, _, _, err = drv.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "role",
		Config: credential.NewConfig(map[string]string{
			"mint_method": "sts_assume_role",
			"role_arn":    "arn:aws:iam::123456789012:role/App",
			"ttl":         "1h",
		}),
	})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	var lastAssume string
	for _, r := range requests {
		if r.action == "AssumeRole" {
			lastAssume = r.scope
		}
	}
	assert.Contains(t, lastAssume, "AKIAOLDEXAMPLEKEY000",
		"a failed commit must not leave the instance signing with the key it could not verify")
}

// TestAWSDriver_CommitRotation_SwapsAfterVerify: the happy path still swaps, and
// the next mint signs with the new key.
func TestAWSDriver_CommitRotation_SwapsAfterVerify(t *testing.T) {
	stub := newConcurrentSTSStub(t)

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAOLDEXAMPLEKEY000",
		"secret_access_key": "old-secret",
		"region":            "us-east-1",
		"sts_endpoint":      stub.srv.URL,
	}), log)
	require.NoError(t, err)
	awsDrv := drv.(*AWSDriver)

	require.NoError(t, awsDrv.CommitRotation(context.TODO(), map[string]string{
		"access_key_id":     "AKIANEWEXAMPLEKEY000",
		"secret_access_key": "new-secret",
		"region":            "us-east-1",
		"sts_endpoint":      stub.srv.URL,
	}))

	_, _, _, _, err = drv.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "role",
		Config: credential.NewConfig(map[string]string{
			"mint_method": "sts_assume_role",
			"role_arn":    "arn:aws:iam::123456789012:role/App",
			"ttl":         "1h",
		}),
	})
	require.NoError(t, err)
	assert.Contains(t, lastAssumeRoleScope(t, stub), "AKIANEWEXAMPLEKEY000")
}

// TestAWSDriver_CleanupRotation_DeactivatesThenDeletes: the order is what makes an
// interrupted cleanup attributable to this source at the next prepare.
func TestAWSDriver_CleanupRotation_DeactivatesThenDeletes(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)
	var calls []iamCall
	var mu sync.Mutex
	iamSrv := iamStub(t, &calls, &mu, iamStubOpts{})

	awsDrv := rotationDriver(t, stsSrv.srv.URL, iamSrv.URL, "AKIANEWEXAMPLEKEY000")

	require.NoError(t, awsDrv.CleanupRotation(context.TODO(), map[string]string{
		"access_key_id": "AKIAOLDEXAMPLEKEY000",
	}))

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{"UpdateAccessKey", "DeleteAccessKey"}, iamActionsOf(calls))
	assert.Equal(t, "Inactive", calls[0].status)
	for _, c := range calls {
		assert.Equal(t, "AKIAOLDEXAMPLEKEY000", c.keyID)
	}
}

// TestAWSDriver_CleanupRotation_ToleratesAlreadyGone: cleanup is retried on a
// schedule, so a key deleted out of band must not keep it retrying forever.
func TestAWSDriver_CleanupRotation_ToleratesAlreadyGone(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)
	var calls []iamCall
	var mu sync.Mutex
	iamSrv := iamStub(t, &calls, &mu, iamStubOpts{noSuchEntity: true})

	awsDrv := rotationDriver(t, stsSrv.srv.URL, iamSrv.URL, "AKIANEWEXAMPLEKEY000")

	require.NoError(t, awsDrv.CleanupRotation(context.TODO(), map[string]string{
		"access_key_id": "AKIAOLDEXAMPLEKEY000",
	}))
}

// =============================================================================
// Config validation
// =============================================================================

func TestAWSSessionSeconds(t *testing.T) {
	tests := []struct {
		name   string
		dur    time.Duration
		want   int32
		errMsg string
	}{
		{name: "minimum", dur: 15 * time.Minute, want: 900},
		{name: "typical", dur: time.Hour, want: 3600},
		{name: "maximum", dur: 12 * time.Hour, want: 43200},
		{name: "below minimum", dur: 899 * time.Second, errMsg: "at least 15m0s"},
		{name: "far below minimum", dur: 5 * time.Minute, errMsg: "at least 15m0s"},
		{name: "above maximum", dur: 12*time.Hour + time.Second, errMsg: "at most 12h0m0s"},
		// Without the range check this wraps int32 into a negative number, which
		// the service would read as something else entirely.
		{name: "would overflow int32", dur: 100000 * time.Hour, errMsg: "at most 12h0m0s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := awsSessionSeconds(tt.dur, "ttl")
			if tt.errMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Contains(t, err.Error(), "'ttl'", "the error must name the config key")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAWSSessionName(t *testing.T) {
	tests := []struct {
		name     string
		specName string
		override string
		want     string
		wantErr  bool
	}{
		{name: "derived from spec name", specName: "prod-keys", want: "warden-prod-keys"},
		{name: "explicit override", specName: "x", override: "my.session@1", want: "my.session@1"},
		{name: "override at max length", specName: "x", override: strings.Repeat("a", 64), want: strings.Repeat("a", 64)},
		{name: "override too long", specName: "x", override: strings.Repeat("a", 65), wantErr: true},
		{name: "override too short", specName: "x", override: "a", wantErr: true},
		{name: "illegal character", specName: "x", override: "has space", wantErr: true},
		// A spec name AWS will not accept must be reported against the spec, not
		// left to fail every mint with a service-side error.
		{name: "spec name yields an invalid default", specName: "keys/for/prod", wantErr: true},
		{name: "spec name too long for the default", specName: strings.Repeat("a", 60), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := map[string]string{}
			if tt.override != "" {
				cfg["session_name"] = tt.override
			}
			got, err := awsSessionName(&credential.CredSpec{Name: tt.specName, Config: credential.NewConfig(cfg)})
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not accepted by AWS")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRedshiftLeaseTTL(t *testing.T) {
	t.Run("no expiration falls back to the requested duration", func(t *testing.T) {
		ttl, err := redshiftLeaseTTL(1800, nil)
		require.NoError(t, err)
		assert.Equal(t, 30*time.Minute, ttl)
	})

	t.Run("future expiration wins", func(t *testing.T) {
		exp := time.Now().Add(10 * time.Minute)
		ttl, err := redshiftLeaseTTL(1800, &exp)
		require.NoError(t, err)
		assert.Less(t, ttl, 30*time.Minute)
		assert.Greater(t, ttl, 9*time.Minute)
	})

	t.Run("past expiration is an error, not the full duration", func(t *testing.T) {
		exp := time.Now().Add(-time.Minute)
		_, err := redshiftLeaseTTL(1800, &exp)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

// TestAWSDriver_MintViaSTSAssumeRole_TTLBelowSTSMinimum: a sub-15m ttl reaches the
// operator as an error naming the key, instead of an opaque service rejection.
func TestAWSDriver_MintViaSTSAssumeRole_TTLBelowSTSMinimum(t *testing.T) {
	stub := newConcurrentSTSStub(t)

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "secret",
		"region":            "us-east-1",
		"sts_endpoint":      stub.srv.URL,
	}), log)
	require.NoError(t, err)

	_, _, _, _, err = drv.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "role",
		Config: credential.NewConfig(map[string]string{
			"mint_method": "sts_assume_role",
			"role_arn":    "arn:aws:iam::123456789012:role/App",
			"ttl":         "5m",
		}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 15m0s")

	mu := &stub.mu
	mu.Lock()
	defer mu.Unlock()
	for _, r := range stub.requests {
		assert.NotEqual(t, "AssumeRole", r.action, "an out-of-range ttl must not reach the service")
	}
}

func TestAWSValidateConfig_EndpointAndActivationDelay(t *testing.T) {
	factory := &AWSDriverFactory{}
	base := func() map[string]string {
		return map[string]string{
			"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
			"secret_access_key": "secret",
			"region":            "us-east-1",
		}
	}

	tests := []struct {
		name   string
		mutate func(map[string]string)
		errMsg string
	}{
		{name: "valid activation delay", mutate: func(c map[string]string) { c["activation_delay"] = "10m" }},
		{
			name:   "malformed activation delay",
			mutate: func(c map[string]string) { c["activation_delay"] = "5 minutes" },
			errMsg: "activation_delay",
		},
		{name: "valid endpoints", mutate: func(c map[string]string) {
			c["sts_endpoint"] = "https://sts.us-east-1.amazonaws.com"
			c["secretsmanager_endpoint"] = "http://127.0.0.1:4566"
		}},
		{
			name:   "endpoint without a scheme",
			mutate: func(c map[string]string) { c["sts_endpoint"] = "sts.us-east-1.amazonaws.com" },
			errMsg: "http or https",
		},
		{
			name:   "endpoint with an unsupported scheme",
			mutate: func(c map[string]string) { c["secretsmanager_endpoint"] = "ftp://example.com" },
			errMsg: "http or https",
		},
		{
			name:   "endpoint with no host",
			mutate: func(c map[string]string) { c["sts_endpoint"] = "https://" },
			errMsg: "no host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.mutate(cfg)
			err := factory.ValidateConfig(credential.NewConfig(cfg))
			if tt.errMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// TestAWSValidateRotationConfig: rotation reaches the real account through IAM,
// which has no override, so pairing it with a redirected source would loop.
func TestAWSValidateRotationConfig(t *testing.T) {
	factory := &AWSDriverFactory{}

	require.NoError(t, factory.ValidateRotationConfig(credential.NewConfig(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "secret",
		"region":            "us-east-1",
	})))

	for _, key := range []string{"sts_endpoint", "secretsmanager_endpoint"} {
		t.Run(key, func(t *testing.T) {
			err := factory.ValidateRotationConfig(credential.NewConfig(map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
				key:                 "http://127.0.0.1:4566",
			}))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rotation_period cannot be set")
		})
	}
}

// =============================================================================
// Templated secret_id
// =============================================================================

// recordingSMStub records the SecretId of every GetSecretValue it is asked for, so
// a test can tell which secret a templated spec actually reached for — and whether
// it reached for one at all.
func recordingSMStub(t *testing.T, secretIDs *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SecretId string `json:"SecretId"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		*secretIDs = append(*secretIDs, body.SecretId)

		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Name":"` + body.SecretId + `","SecretString":"{\"api_key\":\"k-for-` + body.SecretId + `\"}"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// federatedSecretsManagerDriver builds a keyless driver whose STS and Secrets
// Manager calls both land on stubs.
func federatedSecretsManagerDriver(t *testing.T, stsURL, smURL string) *AWSDriver {
	t.Helper()
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"auth_method":             "oidc_federation",
		"region":                  "us-east-1",
		"sts_endpoint":            stsURL,
		"secretsmanager_endpoint": smURL,
	}), log)
	require.NoError(t, err)
	return drv.(*AWSDriver)
}

func TestAWSDriver_TemplatedSecretID(t *testing.T) {
	tests := []struct {
		name        string
		secretID    string
		userClaims  map[string]string
		agentClaims map[string]string
		wantFetched string
		errMsg      string
	}{
		{
			name:        "user claim selects the secret",
			secretID:    "prod/users/{{user.sub}}/datadog",
			userClaims:  map[string]string{"sub": "alice"},
			agentClaims: map[string]string{"sub": "runner"},
			wantFetched: "prod/users/alice/datadog",
		},
		{
			name:        "agent claim selects the secret",
			secretID:    "prod/agents/{{agent.sub}}/keys",
			agentClaims: map[string]string{"sub": "build-runner"},
			wantFetched: "prod/agents/build-runner/keys",
		},
		{
			name:        "both namespaces compose",
			secretID:    "{{agent.team}}/{{user.sub}}",
			userClaims:  map[string]string{"sub": "alice"},
			agentClaims: map[string]string{"team": "platform"},
			wantFetched: "platform/alice",
		},
		{
			name:        "untemplated id is unchanged",
			secretID:    "prod/datadog/keys",
			userClaims:  map[string]string{"sub": "alice"},
			agentClaims: map[string]string{"sub": "runner"},
			wantFetched: "prod/datadog/keys",
		},
		{
			// An ARN carries ':' and '/', neither of which the template scanner
			// touches, so it must pass through byte for byte.
			name:        "arn form is unchanged",
			secretID:    "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/datadog-AbCdEf",
			agentClaims: map[string]string{"sub": "runner"},
			wantFetched: "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/datadog-AbCdEf",
		},
		{
			name:        "absent claim fails closed",
			secretID:    "prod/users/{{user.sub}}/datadog",
			agentClaims: map[string]string{"sub": "runner"},
			errMsg:      "absent from the user's projected claims",
		},
		{
			name:        "value that would escape the path fails closed",
			secretID:    "prod/users/{{user.sub}}/datadog",
			userClaims:  map[string]string{"sub": "../admin"},
			agentClaims: map[string]string{"sub": "runner"},
			errMsg:      "rejected by the allow-list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stsSrv := newConcurrentSTSStub(t)
			var fetched []string
			smSrv := recordingSMStub(t, &fetched)

			drv := federatedSecretsManagerDriver(t, stsSrv.srv.URL, smSrv.URL)
			spec := &credential.CredSpec{Name: "sm", Config: credential.NewConfig(map[string]string{
				"mint_method": "secrets_manager",
				"secret_id":   tt.secretID,
				"role_arn":    "arn:aws:iam::123456789012:role/App",
			})}

			rawData, _, _, _, err := drv.MintCredentialWithExchange(context.TODO(), spec,
				&credential.ExchangeInputs{
					SubjectToken:     "eyJ.warden.assertion",
					SubjectTokenType: credential.TokenTypeJWT,
					UserClaims:       tt.userClaims,
					AgentClaims:      tt.agentClaims,
				})

			if tt.errMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Contains(t, err.Error(), "secret_id", "the error must name the config key")
				assert.Empty(t, fetched, "a template that cannot be resolved must reach no store")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []string{tt.wantFetched}, fetched)
			assert.Equal(t, "k-for-"+tt.wantFetched, rawData["api_key"])
		})
	}
}

// TestAWSDriver_TemplatedSecretID_StaticPathFailsClosed: the non-exchange path has
// no verified claims to resolve from, so a templated id must fail rather than be
// sent as written. A store would return a secret literally named "{{user.sub}}" to
// anyone able to create one.
func TestAWSDriver_TemplatedSecretID_StaticPathFailsClosed(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)
	var fetched []string
	smSrv := recordingSMStub(t, &fetched)

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":           "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key":       "secret",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.srv.URL,
		"secretsmanager_endpoint": smSrv.URL,
	}), log)
	require.NoError(t, err)

	_, _, _, _, err = drv.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "sm",
		Config: credential.NewConfig(map[string]string{
			"mint_method": "secrets_manager",
			"secret_id":   "prod/users/{{user.sub}}/datadog",
		}),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absent from the user's projected claims")
	assert.Empty(t, fetched, "nothing may be fetched when the template cannot resolve")
}

// TestAWSAssertionResource_TemplatedSecretIDStaysRaw pins the deliberate choice:
// the claim is minted before the exchange that would produce the claims, so it
// carries the spec's coordinate rather than the resolved one — the same as every
// other templated coordinate in the assertion layer.
func TestAWSAssertionResource_TemplatedSecretIDStaysRaw(t *testing.T) {
	got, ok := awsAssertionResource(credential.NewConfig(map[string]string{
		"mint_method": "secrets_manager",
		"secret_id":   "prod/users/{{user.sub}}/datadog",
	}))
	require.True(t, ok)
	assert.Equal(t, "aws-secretsmanager:prod/users/{{user.sub}}/datadog", got)
}

// =============================================================================
// secret_read
// =============================================================================

// TestAWSDriver_SecretRead_Static_HappyPath pins the contract that makes this
// method usable as a chaining source: the whole payload is vended under its own
// key names, with no lease. A referenced credential carrying a lease is refused
// outright by the chaining machinery, so the empty leaseID is load-bearing.
func TestAWSDriver_SecretRead_Static_HappyPath(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)

	var target, authScope string
	smSrv := smStub(t, `{"api_key":"dd-key","application_key":"dd-app-key"}`, &target, &authScope)
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":           "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key":       "secret",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.srv.URL,
		"secretsmanager_endpoint": smSrv.URL,
	}), log)
	require.NoError(t, err)

	rawData, metadata, ttl, leaseID, err := drv.MintCredential(context.TODO(), &credential.CredSpec{
		Name:   "datadog-keys",
		Config: credential.NewConfig(map[string]string{"mint_method": "secret_read", "secret_id": "prod/datadog/keys"}),
	})
	require.NoError(t, err)
	assert.Contains(t, target, "GetSecretValue")
	assert.Equal(t, "dd-key", rawData["api_key"])
	assert.Equal(t, "dd-app-key", rawData["application_key"])
	assert.Nil(t, metadata)
	assert.Equal(t, time.Duration(0), ttl)
	assert.Equal(t, "", leaseID, "a chaining source must vend no lease")

	// The payload has to survive parsing with every key intact, which is the whole
	// point of the type this method infers.
	cred, err := types.NewKeyValueCredType().Parse(rawData, metadata, ttl, leaseID)
	require.NoError(t, err)
	require.NoError(t, types.NewKeyValueCredType().Validate(cred))
	assert.Equal(t, credential.TypeKeyValue, cred.Type)
	assert.Equal(t, "dd-key", cred.Data["api_key"])
	assert.Equal(t, "dd-app-key", cred.Data["application_key"])
	assert.False(t, cred.Revocable)
}

func TestAWSDriver_SecretRead_WebIdentity_HappyPath(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)

	var target, authScope string
	smSrv := smStub(t, `{"api_key":"dd-key","application_key":"dd-app-key"}`, &target, &authScope)
	defer smSrv.Close()

	drv := federatedSecretsManagerDriver(t, stsSrv.srv.URL, smSrv.URL)

	rawData, _, ttl, leaseID, err := drv.MintCredentialWithExchange(context.TODO(),
		&credential.CredSpec{Name: "datadog-keys", Config: credential.NewConfig(map[string]string{
			"mint_method": "secret_read",
			"secret_id":   "prod/datadog/keys",
			"role_arn":    "arn:aws:iam::123456789012:role/App",
		})},
		&credential.ExchangeInputs{SubjectToken: "eyJ.warden.assertion", SubjectTokenType: credential.TokenTypeJWT})
	require.NoError(t, err)
	assert.Contains(t, target, "GetSecretValue")
	assert.Contains(t, authScope, "ASIAEXAMPLE", "the fetch must be signed with the federated credentials")
	assert.Equal(t, "dd-key", rawData["api_key"])
	assert.Equal(t, time.Duration(0), ttl)
	assert.Equal(t, "", leaseID)
}

// TestAWSDriver_SecretRead_SelectionKeys: secret_read reads the same store as
// secrets_manager, so it honours the same projection and revision keys.
func TestAWSDriver_SecretRead_SelectionKeys(t *testing.T) {
	stsSrv := newConcurrentSTSStub(t)

	var gotBody map[string]string
	smSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"Name":"prod/app","SecretString":"{\"k\":\"v\",\"drop\":\"me\"}"}`))
	}))
	defer smSrv.Close()

	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := (&AWSDriverFactory{}).Create(credential.NewConfig(map[string]string{
		"access_key_id":           "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key":       "secret",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.srv.URL,
		"secretsmanager_endpoint": smSrv.URL,
	}), log)
	require.NoError(t, err)

	rawData, _, _, _, err := drv.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "sm",
		Config: credential.NewConfig(map[string]string{
			"mint_method":   "secret_read",
			"secret_id":     "prod/app",
			"version_stage": "AWSPREVIOUS",
			"version_id":    "abc-123",
			"json_key_map":  "k=api_key",
		}),
	})
	require.NoError(t, err)
	assert.Equal(t, "AWSPREVIOUS", gotBody["VersionStage"])
	assert.Equal(t, "abc-123", gotBody["VersionId"])
	assert.Equal(t, "v", rawData["api_key"])
	assert.NotContains(t, rawData, "drop", "an unnamed key must not be vended")
}

func TestAWSDriverFactory_InferCredentialType_SecretRead(t *testing.T) {
	factory := &AWSDriverFactory{}

	got, err := factory.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "secret_read"}))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeKeyValue, got)

	// There is no shape to select when the payload is vended verbatim.
	_, err = factory.InferCredentialType(credential.NewConfig(map[string]string{"mint_method": "secret_read", "credential_type": "api_key"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "credential_type is only valid with mint_method=secrets_manager")
}

// TestAWSDriver_SecretRead_StaticSourceRefusesExchange: a chaining source must set
// subject_token_source, which forces the exchange path, which a static source
// cannot serve. The spec writes fine — the store skips test-minting an exchange
// spec — so mint time is the only place this is enforced.
//
// The guard itself predates secret_read and fires before the mint-method switch;
// this pins that secret_read inherits it rather than routing around it.
func TestAWSDriver_SecretRead_StaticSourceRefusesExchange(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{})},
		logger:     log,
	}

	_, _, _, _, err := drv.MintCredentialWithExchange(context.TODO(),
		&credential.CredSpec{Name: "sm", Config: credential.NewConfig(map[string]string{
			"mint_method": "secret_read", "secret_id": "prod/app", "role_arn": "arn:aws:iam::1:role/R",
		})},
		&credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenType: credential.TokenTypeJWT})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires auth_method=oidc_federation on the source")
}

func TestAWSAssertionResource_SecretRead(t *testing.T) {
	got, ok := awsAssertionResource(credential.NewConfig(map[string]string{
		"mint_method": "secret_read",
		"secret_id":   "prod/datadog/keys",
	}))
	require.True(t, ok)
	assert.Equal(t, "aws-secretsmanager:prod/datadog/keys", got)
}

func TestAWSDriver_SecretRead_UnsupportedMethodMessages(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})

	static := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: credential.NewConfig(map[string]string{
			"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "secret", "region": "us-east-1",
		})},
		logger: log,
		region: "us-east-1",
	}
	primeClients(static)

	_, _, _, _, err := static.MintCredential(context.TODO(),
		&credential.CredSpec{Name: "x", Config: credential.NewConfig(map[string]string{"mint_method": "nope"})})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "'secret_read'")

	federated := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS,
			Config: credential.NewConfig(map[string]string{"auth_method": "oidc_federation"})},
		logger: log,
	}
	_, _, _, _, err = federated.MintCredentialWithExchange(context.TODO(),
		&credential.CredSpec{Name: "x", Config: credential.NewConfig(map[string]string{"mint_method": "nope"})},
		&credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenType: credential.TokenTypeJWT})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret_read")
}
