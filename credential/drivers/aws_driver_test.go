package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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
		config  map[string]string
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid minimal config",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
			},
			wantErr: false,
		},
		{
			name: "valid config with assume_role_arn",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
				"assume_role_arn":   "arn:aws:iam::123456789012:role/test-role",
				"external_id":       "ext-123",
				"session_name":      "my-session",
				"session_duration":  "2h",
			},
			wantErr: false,
		},
		{
			name: "valid config with endpoint overrides",
			config: map[string]string{
				"access_key_id":           "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key":       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":                  "us-east-1",
				"sts_endpoint":            "https://sts.us-east-1.amazonaws.com",
				"secretsmanager_endpoint": "https://secretsmanager.us-east-1.amazonaws.com",
			},
			wantErr: false,
		},
		{
			name: "endpoint overrides on a federation source",
			config: map[string]string{
				"auth_method":             "oidc_federation",
				"region":                  "us-east-1",
				"sts_endpoint":            "https://sts.us-east-1.amazonaws.com",
				"secretsmanager_endpoint": "https://secretsmanager.us-east-1.amazonaws.com",
			},
			wantErr: false,
		},
		{
			name: "missing access_key_id",
			config: map[string]string{
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
			},
			wantErr: true,
			errMsg:  "access_key_id",
		},
		{
			name: "missing secret_access_key",
			config: map[string]string{
				"access_key_id": "AKIAIOSFODNN7EXAMPLE",
				"region":        "us-east-1",
			},
			wantErr: true,
			errMsg:  "secret_access_key",
		},
		{
			name: "missing region",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
			wantErr: true,
			errMsg:  "region",
		},
		{
			name: "invalid session_duration",
			config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"region":            "us-east-1",
				"session_duration":  "invalid",
			},
			wantErr: true,
			errMsg:  "session_duration",
		},
		{
			name:    "oidc_federation valid without keys",
			config:  map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"},
			wantErr: false,
		},
		{
			name:    "oidc_federation rejects static keys",
			config:  map[string]string{"auth_method": "oidc_federation", "region": "us-east-1", "access_key_id": "AKIA..."},
			wantErr: true,
			errMsg:  "must not be set for auth_method=oidc_federation",
		},
		{
			name:    "oidc_federation rejects assume_role_arn",
			config:  map[string]string{"auth_method": "oidc_federation", "region": "us-east-1", "assume_role_arn": "arn:aws:iam::1:role/x"},
			wantErr: true,
			errMsg:  "assume_role_arn is not supported",
		},
		{
			name:    "invalid auth_method",
			config:  map[string]string{"auth_method": "bogus", "region": "us-east-1"},
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
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeAWS, driver.Type())
}

func TestAWSDriver_Cleanup(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: map[string]string{},
		},
	}
	err := driver.Cleanup(context.TODO())
	assert.NoError(t, err)
}

func TestAWSDriver_Revoke_STS(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type:   credential.SourceTypeAWS,
			Config: map[string]string{},
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
					Config: map[string]string{
						"access_key_id": tt.accessKey,
					},
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
			Config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			},
		},
		region: "us-east-1",
	}
	// Build clients so authenticate doesn't fail (no assume_role_arn)
	primeClients(driver)

	spec := &credential.CredSpec{
		Name: "test-spec",
		Type: credential.TypeAWSAccessKeys,
		Config: map[string]string{
			"mint_method": "invalid",
		},
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported mint_method")
}

func TestAWSDriver_MintCredential_TTLBelowMinimum(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAWS,
			Config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			},
		},
		region: "us-east-1",
	}
	primeClients(driver)

	spec := &credential.CredSpec{
		Name:   "test-spec",
		Type:   credential.TypeAWSAccessKeys,
		MinTTL: 2 * time.Hour,
		Config: map[string]string{
			"mint_method": "sts_assume_role",
			"role_arn":    "arn:aws:iam::123456789012:role/test-role",
			"ttl":         "30m", // Below MinTTL of 2h
		},
	}

	_, _, _, _, err := driver.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestAWSDriver_MintCredential_TTLExceedsMaximum(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{
			Type: credential.SourceTypeAWS,
			Config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			},
		},
		region: "us-east-1",
	}
	primeClients(driver)

	spec := &credential.CredSpec{
		Name:   "test-spec",
		Type:   credential.TypeAWSAccessKeys,
		MaxTTL: 1 * time.Hour,
		Config: map[string]string{
			"mint_method": "sts_assume_role",
			"role_arn":    "arn:aws:iam::123456789012:role/test-role",
			"ttl":         "4h", // Above MaxTTL of 1h
		},
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
			Config: map[string]string{},
		},
	}
	assert.Equal(t, credential.SourceTypeAWS, driver.Type())
}

// =============================================================================
// AWSDriver redshift_iam_token tests
// =============================================================================

func TestAWSDriverFactory_InferCredentialType_Redshift(t *testing.T) {
	factory := &AWSDriverFactory{}

	credType, err := factory.InferCredentialType(map[string]string{
		"mint_method": "redshift_iam_token",
	})
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
			got, err := factory.InferCredentialType(cfg)
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
		_, err := factory.InferCredentialType(map[string]string{
			"mint_method":     "sts_assume_role",
			"credential_type": credential.TypeAPIKey,
		})
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
			Config: map[string]string{
				"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
				"secret_access_key": "secret",
				"region":            "us-east-1",
			},
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
		Config: map[string]string{
			"mint_method":        "redshift_iam_token",
			"cluster_identifier": "my-cluster",
		},
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
		Config: map[string]string{
			"mint_method": "redshift_iam_token",
			"db_endpoint": "my-cluster.redshift.amazonaws.com",
		},
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
		Config: map[string]string{
			"mint_method":        "redshift_iam_token",
			"db_endpoint":        "x",
			"cluster_identifier": "my-cluster",
			"workgroup_name":     "my-wg",
		},
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
				Config: map[string]string{
					"mint_method":        "redshift_iam_token",
					"db_endpoint":        "x",
					"cluster_identifier": "my-cluster",
					"duration_seconds":   d,
				},
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
		Config: map[string]string{
			"mint_method": "definitely-not-real",
		},
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
	drv, err := factory.Create(map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"}, log)
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
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "oidc_federation"}},
		logger:     log,
	}
	for _, mm := range []string{"secrets_manager", "sts_assume_role"} {
		_, _, _, _, err := wifDrv.MintCredential(context.TODO(), &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": mm}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires subject_token_source on the spec (warden_identity or agent_identity)")
	}
}

// TestAWSDriver_MintCredentialWithExchange_Guards covers the exchange-path guards
// before any network call.
func TestAWSDriver_MintCredentialWithExchange_Guards(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "oidc_federation"}},
		logger:     log,
	}
	roleSpec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "sts_assume_role", "role_arn": "arn:aws:iam::1:role/x"}}
	verified := &credential.ExchangeInputs{SubjectToken: "eyJ"}

	// A static source must not reach the federation path.
	staticDrv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "static"}},
		logger:     log,
	}
	_, _, _, _, err := staticDrv.MintCredentialWithExchange(context.TODO(), roleSpec, verified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method=oidc_federation")

	// A mint_method with no federation support is rejected before any STS call.
	_, _, _, _, err = drv.MintCredentialWithExchange(context.TODO(), &credential.CredSpec{Config: map[string]string{"mint_method": "rds_iam_token"}}, verified)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported over auth_method=oidc_federation")

	// Missing subject.
	_, _, _, _, err = drv.MintCredentialWithExchange(context.TODO(), roleSpec, &credential.ExchangeInputs{})
	require.Error(t, err)

	// For sts_assume_role, the requested TTL is bound-checked before any STS call.
	boundedSpec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "sts_assume_role", "role_arn": "arn:aws:iam::1:role/x", "ttl": "2h"}, MaxTTL: time.Hour}
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
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"}},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
	}
	spec := &credential.CredSpec{Name: "wid", Config: map[string]string{
		"mint_method": "sts_assume_role",
		"role_arn":    "arn:aws:iam::123456789012:role/App",
		"ttl":         "15m",
	}}
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
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"}},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
	}
	spec := &credential.CredSpec{Name: "wid", Config: map[string]string{
		"mint_method": "sts_assume_role",
		"role_arn":    "arn:aws:iam::123456789012:role/App",
		"ttl":         "15m",
	}}
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
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"}},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(stsSrv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
		smBaseEndpoint: smSrv.URL,
	}
	spec := &credential.CredSpec{Name: "app", Config: map[string]string{
		"mint_method": "secrets_manager",
		"secret_id":   "prod/app/keys",
		"role_arn":    "arn:aws:iam::123456789012:role/WardenSecretsReader",
	}}
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
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "oidc_federation", "region": "us-east-1"}},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(stsSrv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
		smBaseEndpoint: smSrv.URL,
	}
	spec := &credential.CredSpec{Name: "openai", Config: map[string]string{
		"mint_method":     "secrets_manager",
		"credential_type": "api_key",
		"secret_id":       "prod/app/openai",
		"role_arn":        "arn:aws:iam::123456789012:role/WardenSecretsReader",
	}}
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
		aud, ok := awsAssertionAudience(map[string]string{"auth_method": "oidc_federation"})
		require.True(t, ok)
		assert.Equal(t, "sts.amazonaws.com", aud)
	})

	t.Run("federation explicit override", func(t *testing.T) {
		aud, ok := awsAssertionAudience(map[string]string{"auth_method": "oidc_federation", "audience": "my-client-id"})
		require.True(t, ok)
		assert.Equal(t, "my-client-id", aud)
	})

	t.Run("static source derives nothing", func(t *testing.T) {
		_, ok := awsAssertionAudience(map[string]string{"auth_method": "static"})
		assert.False(t, ok)
	})

	t.Run("routed via DeriveAssertionAudience", func(t *testing.T) {
		aud, ok := DeriveAssertionAudience(credential.SourceTypeAWS, map[string]string{"auth_method": "oidc_federation"}, map[string]string{})
		require.True(t, ok)
		assert.Equal(t, "sts.amazonaws.com", aud)
	})
}

func TestAWSValidateConfig_AudienceOnlyFederation(t *testing.T) {
	f := &AWSDriverFactory{}

	t.Run("audience rejected on static", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"auth_method":       "static",
			"access_key_id":     "AKIA",
			"secret_access_key": "sk",
			"region":            "us-east-1",
			"audience":          "sts.amazonaws.com",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only valid for auth_method=oidc_federation")
	})

	t.Run("audience allowed on federation", func(t *testing.T) {
		err := f.ValidateConfig(map[string]string{
			"auth_method": "oidc_federation",
			"region":      "us-east-1",
			"audience":    "my-client-id",
		})
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
	drv, err := (&AWSDriverFactory{}).Create(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region":            "us-east-1",
		"sts_endpoint":      srv.URL,
	}, log)
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
	_, err := (&AWSDriverFactory{}).Create(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region":            "us-east-1",
		"assume_role_arn":   "arn:aws:iam::123456789012:role/WardenSourceRole",
		"sts_endpoint":      srv.URL,
	}, log)
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
	drv, err := (&AWSDriverFactory{}).Create(map[string]string{
		"access_key_id":           "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key":       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.URL,
		"secretsmanager_endpoint": smSrv.URL,
	}, log)
	require.NoError(t, err)

	rawData, _, _, _, err := drv.MintCredential(context.TODO(), &credential.CredSpec{
		Name:   "sm",
		Config: map[string]string{"mint_method": "secrets_manager", "secret_id": "prod/app"},
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
	drv, err := (&AWSDriverFactory{}).Create(map[string]string{
		"auth_method":             "oidc_federation",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.URL,
		"secretsmanager_endpoint": smSrv.URL,
	}, log)
	require.NoError(t, err)

	spec := &credential.CredSpec{Name: "sm", Config: map[string]string{
		"mint_method": "secrets_manager",
		"secret_id":   "prod/app",
		"role_arn":    "arn:aws:iam::123456789012:role/App",
	}}
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
	drv, err := (&AWSDriverFactory{}).Create(map[string]string{
		"auth_method": "oidc_federation",
		"region":      "us-east-1",
	}, log)
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

		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "GetCallerIdentity":
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/w</Arn><UserId>AIDA</UserId><Account>123456789012</Account></GetCallerIdentityResult>
</GetCallerIdentityResponse>`))
		default:
			_, _ = w.Write([]byte(`<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>secretexample</SecretAccessKey>
      <SessionToken>tokenexample</SessionToken>
      <Expiration>2035-01-01T00:00:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/App/w</Arn><AssumedRoleId>AROA:w</AssumedRoleId></AssumedRoleUser>
  </AssumeRoleResult>
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
	drv, err := (&AWSDriverFactory{}).Create(baseConfig, log)
	require.NoError(t, err)
	awsDrv := drv.(*AWSDriver)

	roleSpec := &credential.CredSpec{Name: "role", Config: map[string]string{
		"mint_method": "sts_assume_role", "role_arn": "arn:aws:iam::123456789012:role/App", "ttl": "1h",
	}}
	smSpec := &credential.CredSpec{Name: "sm", Config: map[string]string{
		"mint_method": "secrets_manager", "secret_id": "prod/app",
	}}

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
	drv, err := (&AWSDriverFactory{}).Create(baseConfig, log)
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
	assert.Contains(t, lastAssumeRoleScope(t, stub),"AKIAOLDEXAMPLEKEY000",
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
	assert.Contains(t, lastAssumeRoleScope(t, stub),"AKIANEWEXAMPLEKEY000")
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
	_, err := (&AWSDriverFactory{}).Create(map[string]string{
		"access_key_id":     "AKIAIOSFODNN7EXAMPLE",
		"secret_access_key": "secret",
		"region":            "us-east-1",
		"sts_endpoint":      srv.URL,
	}, log)
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

	_, err := (&AWSDriverFactory{}).Create(cfg, log)
	require.Error(t, err, "without tls_skip_verify the untrusted certificate must be rejected")

	cfg["tls_skip_verify"] = "true"
	_, err = (&AWSDriverFactory{}).Create(cfg, log)
	require.NoError(t, err)
	assert.Equal(t, []string{"GetCallerIdentity"}, actions)
}

// TestAWSDriver_MintViaRDSIAMToken_HappyPath covers the RDS path under the snapshot
// signature. The token is signed locally, so no endpoint is involved.
func TestAWSDriver_MintViaRDSIAMToken_HappyPath(t *testing.T) {
	driver := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{
			"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "secret", "region": "us-east-1",
		}},
		baseCreds: credentials.NewStaticCredentialsProvider("AKIAIOSFODNN7EXAMPLE", "secret", ""),
		region:    "us-east-1",
	}
	primeClients(driver)

	rawData, metadata, ttl, leaseID, err := driver.MintCredential(context.TODO(), &credential.CredSpec{
		Name: "db",
		Config: map[string]string{
			"mint_method": "rds_iam_token",
			"db_endpoint": "mydb.abc123.us-east-1.rds.amazonaws.com",
			"db_user":     "app",
		},
	})
	require.NoError(t, err)
	assert.Contains(t, rawData["auth_token"], "X-Amz-Signature=")
	assert.Equal(t, "5432", rawData["db_port"])
	assert.Equal(t, "rds_iam", rawData["token_type"])
	assert.Nil(t, metadata)
	assert.Equal(t, 15*time.Minute, ttl)
	assert.Equal(t, "", leaseID)
}

// iamStub answers the IAM calls rotation makes, recording each action. IAM speaks
// the same query/XML protocol as STS.
// onCreateKey, when set, runs while the CreateAccessKey call is in flight — the
// seam a rotation commit needs to land inside a prepare, after it has snapshotted
// the config and before it builds its result from it.
func iamStub(t *testing.T, actions *[]string, mu *sync.Mutex, onCreateKey func()) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		mu.Lock()
		*actions = append(*actions, action)
		mu.Unlock()

		if action == "CreateAccessKey" && onCreateKey != nil {
			onCreateKey()
		}

		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "ListAccessKeys":
			_, _ = w.Write([]byte(`<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListAccessKeysResult><IsTruncated>false</IsTruncated><AccessKeyMetadata>
    <member><UserName>w</UserName><AccessKeyId>AKIAOLDEXAMPLEKEY000</AccessKeyId><Status>Active</Status></member>
  </AccessKeyMetadata></ListAccessKeysResult>
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
	var iamActions []string
	var iamMu sync.Mutex

	// The interloping commit fires while prepare's CreateAccessKey is in flight:
	// after prepare snapshotted the config, before it builds its result from it.
	iamSrv := iamStub(t, &iamActions, &iamMu, func() {
		if err := awsDrv.CommitRotation(context.TODO(), map[string]string{
			"access_key_id":     "AKIAINTERLOPERKEY000",
			"secret_access_key": "interloper-secret",
			"region":            "us-east-1",
			"sts_endpoint":      stsSrv.srv.URL,
			"activation_delay":  "99m",
		}); err != nil {
			t.Errorf("interloping commit failed: %v", err)
		}
	})

	drv, err := (&AWSDriverFactory{}).Create(baseConfig, log)
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
	drv, err := (&AWSDriverFactory{}).Create(map[string]string{
		"auth_method":             "oidc_federation",
		"region":                  "us-east-1",
		"sts_endpoint":            stsSrv.URL,
		"secretsmanager_endpoint": smSrv.URL,
		"tls_skip_verify":         "true",
	}, log)
	require.NoError(t, err)

	spec := &credential.CredSpec{Name: "sm", Config: map[string]string{
		"mint_method": "secrets_manager",
		"secret_id":   "prod/app",
		"role_arn":    "arn:aws:iam::123456789012:role/App",
	}}
	rawData, _, _, _, err := drv.(*AWSDriver).MintCredentialWithExchange(context.TODO(), spec, &credential.ExchangeInputs{
		SubjectToken:     "eyJ.warden.assertion",
		SubjectTokenType: credential.TokenTypeJWT,
	})
	require.NoError(t, err)
	assert.Contains(t, target, "GetSecretValue")
	assert.Contains(t, authScope, "ASIAEXAMPLE")
	assert.Equal(t, "federated", rawData["api_key"])
}
