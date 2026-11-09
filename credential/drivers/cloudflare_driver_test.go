package drivers

import (
	"context"
	"testing"
	"time"

	"github.com/stephnangue/warden/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createCloudflareTestDriver(t *testing.T) *CloudflareDriver {
	t.Helper()
	driver, err := (&CloudflareDriverFactory{}).Create(credential.NewConfig(nil), createOVHTestLogger())
	require.NoError(t, err)
	return driver.(*CloudflareDriver)
}

func cloudflareSpec(config map[string]string) *credential.CredSpec {
	return &credential.CredSpec{Name: "cf-spec", Type: credential.TypeCloudflareKeys, Config: credential.NewConfig(config)}
}

func TestCloudflareDriverFactory(t *testing.T) {
	f := &CloudflareDriverFactory{}
	assert.Equal(t, credential.SourceTypeCloudflare, f.Type())

	inferred, err := f.InferCredentialType(credential.NewConfig(nil))
	require.NoError(t, err)
	assert.Equal(t, credential.TypeCloudflareKeys, inferred)

	assert.Empty(t, f.SensitiveConfigFields())
	assert.Nil(t, f.StoredSecrets(credential.NewConfig(nil)))

	require.NoError(t, f.ValidateConfig(credential.NewConfig(nil)))

	// The credential is each spec's own, so the reference and its modifiers are
	// refused on the source.
	for key, value := range map[string]string{
		credential.ConfigSecretSpec:     "cf-from-vault",
		credential.ConfigSecretField:    "token",
		credential.ConfigSecretCacheTTL: "10m",
	} {
		err = f.ValidateConfig(credential.NewConfig(map[string]string{key: value}))
		require.Errorf(t, err, "%s on the source", key)
		assert.Contains(t, err.Error(), "'"+key+"' belongs on each cloudflare_keys spec")
	}

	driver := createCloudflareTestDriver(t)
	assert.Equal(t, credential.SourceTypeCloudflare, driver.Type())
	assert.NoError(t, driver.Cleanup(context.Background()))
}

// Each mode the fetched secret can hold is served under the names the Cloudflare
// provider reads, and only the keys present are carried.
func TestCloudflareDriver_MintFromSecret(t *testing.T) {
	driver := createCloudflareTestDriver(t)
	chained := map[string]string{credential.ConfigSecretSpec: "cf-from-vault"}

	for _, tc := range []struct {
		name     string
		spec     map[string]string
		material credential.SecretMaterial
		want     map[string]interface{}
	}{
		{
			name:     "api token",
			spec:     chained,
			material: credential.SecretMaterial{Data: map[string]string{"api_token": "tok"}, Field: "api_token"},
			want:     map[string]interface{}{"api_token": "tok"},
		},
		{
			name:     "R2 pair",
			spec:     chained,
			material: credential.SecretMaterial{Data: map[string]string{"access_key_id": "ak", "secret_access_key": "sk"}},
			want:     map[string]interface{}{"access_key_id": "ak", "secret_access_key": "sk"},
		},
		{
			name:     "both",
			spec:     chained,
			material: credential.SecretMaterial{Data: map[string]string{"api_token": "tok", "access_key_id": "ak", "secret_access_key": "sk"}},
			want:     map[string]interface{}{"api_token": "tok", "access_key_id": "ak", "secret_access_key": "sk"},
		},
		{
			name:     "a single-key secret is the token",
			spec:     chained,
			material: credential.SecretMaterial{Data: map[string]string{"token": "tok"}, Field: "token"},
			want:     map[string]interface{}{"api_token": "tok"},
		},
		{
			name: "secret_field names the token, and wins over api_token",
			spec: map[string]string{credential.ConfigSecretSpec: "cf-from-vault", credential.ConfigSecretField: "cf_token"},
			material: credential.SecretMaterial{
				Data:  map[string]string{"cf_token": "chosen", "api_token": "other", "access_key_id": "ak", "secret_access_key": "sk"},
				Field: "cf_token",
			},
			want: map[string]interface{}{"api_token": "chosen", "access_key_id": "ak", "secret_access_key": "sk"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rawData, metadata, ttl, leaseID, err := driver.MintFromSecret(context.Background(), cloudflareSpec(tc.spec), tc.material)
			require.NoError(t, err)
			assert.Equal(t, tc.want, rawData)
			assert.Nil(t, metadata)
			// Nothing was created, so there is no lease to release.
			assert.Empty(t, leaseID)
			assert.Equal(t, defaultCloudflareChainTTL, ttl)
		})
	}

	t.Run("the spec's secret_cache_ttl bounds how long the credential is reused", func(t *testing.T) {
		spec := cloudflareSpec(map[string]string{credential.ConfigSecretSpec: "cf-from-vault", credential.ConfigSecretCacheTTL: "2m"})
		_, _, ttl, _, err := driver.MintFromSecret(context.Background(), spec, credential.SecretMaterial{Data: map[string]string{"api_token": "tok"}})
		require.NoError(t, err)
		assert.Equal(t, 2*time.Minute, ttl)
	})
}

// An incomplete secret is reported as such, so a cached copy is evicted and the
// chain walked again rather than served.
func TestCloudflareDriver_MintFromSecret_Incomplete(t *testing.T) {
	driver := createCloudflareTestDriver(t)
	spec := cloudflareSpec(map[string]string{credential.ConfigSecretSpec: "cf-from-vault"})

	for _, tc := range []struct {
		name     string
		material credential.SecretMaterial
	}{
		{name: "no secret access key", material: credential.SecretMaterial{Data: map[string]string{"api_token": "tok", "access_key_id": "ak"}}},
		{name: "no access key id", material: credential.SecretMaterial{Data: map[string]string{"secret_access_key": "sk"}, Field: "secret_access_key"}},
		{name: "empty", material: credential.SecretMaterial{Data: map[string]string{}}},
		{name: "unrelated keys", material: credential.SecretMaterial{Data: map[string]string{"user": "u", "password": "p"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := driver.MintFromSecret(context.Background(), spec, tc.material)
			require.Error(t, err)
			assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete)
		})
	}
}

// A field the operator names is where the token is; an empty one is an error, not
// a quiet fall back to api_token.
func TestCloudflareDriver_MintFromSecret_EmptySecretField(t *testing.T) {
	driver := createCloudflareTestDriver(t)
	spec := cloudflareSpec(map[string]string{credential.ConfigSecretSpec: "cf-from-vault", credential.ConfigSecretField: "cf_token"})

	_, _, _, _, err := driver.MintFromSecret(context.Background(), spec, credential.SecretMaterial{
		Data:  map[string]string{"api_token": "tok"},
		Field: "cf_token",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `secret_field "cf_token"`)
	assert.ErrorIs(t, err, credential.ErrChainedSecretIncomplete, "a cached copy missing the field is evicted and refetched")
}

// A typed referenced credential resolves its primary field on its own: an api_key
// spec yields Field "api_key", which is then the token even beside other keys.
func TestCloudflareDriver_MintFromSecret_PrimaryFieldIsTheToken(t *testing.T) {
	driver := createCloudflareTestDriver(t)
	spec := cloudflareSpec(map[string]string{credential.ConfigSecretSpec: "cf-api-key-spec"})

	rawData, _, _, _, err := driver.MintFromSecret(context.Background(), spec, credential.SecretMaterial{
		Data:  map[string]string{"api_key": "tok", "organization_id": "org"},
		Field: "api_key",
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{"api_token": "tok"}, rawData)
}

// The source refuses a reference of its own, but one stored before that check is
// not re-validated against its specs, so the spec's own reference is required here.
func TestCloudflareDriver_MintFromSecret_RequiresOwnSecretSpec(t *testing.T) {
	driver := createCloudflareTestDriver(t)
	_, _, _, _, err := driver.MintFromSecret(context.Background(), cloudflareSpec(nil), credential.SecretMaterial{
		Data: map[string]string{"api_token": "tok"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigSecretSpec)
}

func TestCloudflareDriver_MintCredential_FailsClosed(t *testing.T) {
	driver := createCloudflareTestDriver(t)
	_, _, _, _, err := driver.MintCredential(context.Background(), cloudflareSpec(map[string]string{"api_token": "inline"}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), credential.ConfigSecretSpec)
}

func TestCloudflareDriver_Revoke_IsNoOp(t *testing.T) {
	driver := createCloudflareTestDriver(t)
	for _, leaseID := range []string{"", "junk"} {
		assert.NoError(t, driver.Revoke(context.Background(), leaseID))
	}
}
