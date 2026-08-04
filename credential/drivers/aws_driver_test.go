package drivers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stephnangue/warden/credential"
	"github.com/stephnangue/warden/credential/types"
	"github.com/stephnangue/warden/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestApplyKeyMap(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		keyMap   string
		expected map[string]interface{}
	}{
		{
			name: "basic remapping",
			data: map[string]interface{}{
				"accessKeyId": "AKIA123",
				"secretKey":   "secret123",
			},
			keyMap: "accessKeyId=access_key_id,secretKey=secret_access_key",
			expected: map[string]interface{}{
				"access_key_id":     "AKIA123",
				"secret_access_key": "secret123",
			},
		},
		{
			name: "missing source key",
			data: map[string]interface{}{
				"accessKeyId": "AKIA123",
			},
			keyMap: "accessKeyId=access_key_id,missing=other",
			expected: map[string]interface{}{
				"access_key_id": "AKIA123",
			},
		},
		{
			name: "whitespace handling",
			data: map[string]interface{}{
				"key1": "val1",
			},
			keyMap: " key1 = mapped_key1 ",
			expected: map[string]interface{}{
				"mapped_key1": "val1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyKeyMap(tt.data, tt.keyMap)
			assert.Equal(t, tt.expected, result)
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
	driver.buildClients(driver.baseCreds)
	driver.baseCredsVerified = true

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
	driver.buildClients(driver.baseCreds)
	driver.baseCredsVerified = true

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
	driver.buildClients(driver.baseCreds)
	driver.baseCredsVerified = true

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
	driver.buildClients(driver.baseCreds)
	driver.baseCredsVerified = true
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
		assert.Contains(t, err.Error(), "requires subject_token_source=warden_identity")
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
	verified := &credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenOrigin: credential.ExchangeOriginVerified}

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

	// Unverified origin must be rejected (only Warden-minted assertions allowed).
	_, _, _, _, err = drv.MintCredentialWithExchange(context.TODO(), roleSpec, &credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenOrigin: credential.ExchangeOriginUnverified})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verified subject")

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
		SubjectToken:       "eyJ.warden.assertion",
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginVerified,
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
		SubjectToken:       "eyJ.warden.assertion",
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginVerified,
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
		SubjectToken:       "eyJ.warden.assertion",
		SubjectTokenType:   credential.TokenTypeJWT,
		SubjectTokenOrigin: credential.ExchangeOriginVerified,
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
