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
			name:    "wif valid without keys",
			config:  map[string]string{"auth_method": "wif", "region": "us-east-1"},
			wantErr: false,
		},
		{
			name:    "wif rejects static keys",
			config:  map[string]string{"auth_method": "wif", "region": "us-east-1", "access_key_id": "AKIA..."},
			wantErr: true,
			errMsg:  "must not be set for auth_method=wif",
		},
		{
			name:    "wif rejects assume_role_arn",
			config:  map[string]string{"auth_method": "wif", "region": "us-east-1", "assume_role_arn": "arn:aws:iam::1:role/x"},
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

// TestAWSDriver_Create_WIF_Keyless verifies a wif source is constructed with no
// IAM keys and without an eager credential probe (no network).
func TestAWSDriver_Create_WIF_Keyless(t *testing.T) {
	factory := &AWSDriverFactory{}
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv, err := factory.Create(map[string]string{"auth_method": "wif", "region": "us-east-1"}, log)
	require.NoError(t, err)
	require.NotNil(t, drv)
	awsDrv := drv.(*AWSDriver)
	assert.NotNil(t, awsDrv.anonSTSClient, "wif source must build the anonymous STS client")
}

// TestAWSDriver_MintGuards covers the fail-closed routing between the exchange
// and non-exchange paths.
func TestAWSDriver_MintGuards(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})

	// A static source: the web-identity mint_method requires exchange inputs, so
	// plain MintCredential must refuse it.
	staticDrv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "static"}},
		logger:     log,
	}
	spec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "sts_assume_role_web_identity", "role_arn": "arn:aws:iam::1:role/x"}}
	_, _, _, _, err := staticDrv.MintCredential(context.TODO(), spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires token-exchange inputs")

	// A wif source reached with a non-WIF mint_method must fail clearly, not
	// fall into authenticate() with empty keys.
	wifDrv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "wif"}},
		logger:     log,
	}
	_, _, _, _, err = wifDrv.MintCredential(context.TODO(), &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "secrets_manager"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth_method=wif supports only")
}

// TestAWSDriver_MintCredentialWithExchange_Guards covers the exchange-path guards
// before any network call.
func TestAWSDriver_MintCredentialWithExchange_Guards(t *testing.T) {
	log, _ := logger.NewGatedLogger(nil, logger.GatedWriterConfig{})
	drv := &AWSDriver{
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "wif"}},
		logger:     log,
	}
	roleSpec := &credential.CredSpec{Name: "s", Config: map[string]string{"mint_method": "sts_assume_role_web_identity", "role_arn": "arn:aws:iam::1:role/x"}}

	// Wrong mint_method.
	_, _, _, _, err := drv.MintCredentialWithExchange(context.TODO(), &credential.CredSpec{Config: map[string]string{"mint_method": "sts_assume_role"}}, &credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenOrigin: credential.ExchangeOriginVerified})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sts_assume_role_web_identity")

	// Missing subject.
	_, _, _, _, err = drv.MintCredentialWithExchange(context.TODO(), roleSpec, &credential.ExchangeInputs{})
	require.Error(t, err)

	// Unverified origin must be rejected (only Warden-minted assertions allowed).
	_, _, _, _, err = drv.MintCredentialWithExchange(context.TODO(), roleSpec, &credential.ExchangeInputs{SubjectToken: "eyJ", SubjectTokenOrigin: credential.ExchangeOriginUnverified})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verified subject")
}

// TestAWSDriver_WebIdentity_HappyPath drives the full exchange against a mocked
// STS endpoint, asserting the assertion is forwarded as WebIdentityToken and the
// returned credentials are surfaced.
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
		credSource: &credential.CredSource{Type: credential.SourceTypeAWS, Config: map[string]string{"auth_method": "wif", "region": "us-east-1"}},
		logger:     log,
		region:     "us-east-1",
		anonSTSClient: sts.New(sts.Options{
			Region:       "us-east-1",
			BaseEndpoint: aws.String(srv.URL),
			Credentials:  aws.AnonymousCredentials{},
		}),
	}
	spec := &credential.CredSpec{Name: "wid", Config: map[string]string{
		"mint_method": "sts_assume_role_web_identity",
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

// =============================================================================
// AzureDriver readLimitedBody Test
// =============================================================================
